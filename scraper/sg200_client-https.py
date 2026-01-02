#!/usr/bin/env python3
"""
Cisco SG200 dynamic MAC table collector over HTTPS using requests.Session + legacy TLS support.

This targets legacy SG200 HTTPS stacks that require:
- TLSv1.0 and/or weak ciphers
- unsafe legacy renegotiation

Security posture:
- This weakens TLS significantly (SECLEVEL=0 + legacy renegotiation).
- Use ONLY on a restricted management network/VLAN.

Key references:
- @SECLEVEL in OpenSSL cipher strings: 
- Legacy renegotiation options: 
- Custom SSLContext with requests via HTTPAdapter: 
"""

from __future__ import annotations

import re
import ssl
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional, Tuple
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup
from requests.adapters import HTTPAdapter


DEFAULT_TIMEOUT = 20  # seconds


@dataclass(frozen=True)
class MacEntry:
    switch_ip: str
    vlan: int
    mac: str
    port_index: int


def _normalize_mac(raw: str) -> Optional[str]:
    if raw is None:
        return None
    s = raw.strip().lower()
    s = s.replace("0x", "")
    s = re.sub(r"[^0-9a-f]", "", s)
    if len(s) != 12:
        return None
    return ":".join(s[i : i + 2] for i in range(0, 12, 2))


def _parse_dynamic_mac_table(html: str, switch_ip: str) -> List[MacEntry]:
    """
    SG200 dynamic MAC table page encodes rows as repeated hidden inputs, e.g.:
      dot1qFdbId$repeat?1=1
      dot1qTpFdbAddress$repeat?1=0x001122334455
      dot1qTpFdbPort$repeat?1=52
    """
    soup = BeautifulSoup(html, "html.parser")

    vlan_by_idx: Dict[int, int] = {}
    mac_by_idx: Dict[int, str] = {}
    port_by_idx: Dict[int, int] = {}

    patt = re.compile(r"^(dot1qFdbId|dot1qTpFdbAddress|dot1qTpFdbPort)\$repeat\?(\d+)$")

    for inp in soup.find_all("input"):
        name = inp.get("name") or ""
        value = inp.get("value") or ""

        m = patt.match(name)
        if not m:
            continue

        field = m.group(1)
        idx = int(m.group(2))

        if field == "dot1qFdbId":
            try:
                vlan_by_idx[idx] = int(value)
            except ValueError:
                continue
        elif field == "dot1qTpFdbAddress":
            mac = _normalize_mac(value)
            if mac:
                mac_by_idx[idx] = mac
        elif field == "dot1qTpFdbPort":
            try:
                port_by_idx[idx] = int(value)
            except ValueError:
                continue

    entries: List[MacEntry] = []
    for idx in sorted(set(vlan_by_idx) & set(mac_by_idx) & set(port_by_idx)):
        entries.append(
            MacEntry(
                switch_ip=switch_ip,
                vlan=vlan_by_idx[idx],
                mac=mac_by_idx[idx],
                port_index=port_by_idx[idx],
            )
        )
    return entries


class SSLContextAdapter(HTTPAdapter):
    """
    Make requests use a custom SSLContext by injecting it into urllib3 pool manager.
    
    """
    def __init__(self, ssl_context: ssl.SSLContext, **kwargs):
        self._ssl_context = ssl_context
        super().__init__(**kwargs)

    def init_poolmanager(self, connections, maxsize, block=False, **pool_kwargs):
        pool_kwargs["ssl_context"] = self._ssl_context
        return super().init_poolmanager(connections, maxsize, block=block, **pool_kwargs)

    def proxy_manager_for(self, proxy, **proxy_kwargs):
        proxy_kwargs["ssl_context"] = self._ssl_context
        return super().proxy_manager_for(proxy, **proxy_kwargs)


def _make_sg200_legacy_ssl_context(ignore_cert_errors: bool) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    if ignore_cert_errors:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    else:
        ctx.check_hostname = True
        ctx.verify_mode = ssl.CERT_REQUIRED
        ctx.load_default_certs()

    # Allow TLSv1.0 (some SG200 HTTPS stacks require it).
    try:
        ctx.minimum_version = ssl.TLSVersion.TLSv1
        ctx.maximum_version = ssl.TLSVersion.TLSv1_2
    except Exception:
        # Best-effort fallback for older builds
        ctx.options &= ~getattr(ssl, "OP_NO_TLSv1", 0)
        ctx.options &= ~getattr(ssl, "OP_NO_TLSv1_1", 0)

    # Most permissive OpenSSL security level (legacy compatibility).
    # @SECLEVEL is documented in OpenSSL cipher string syntax. 
    ctx.set_ciphers("ALL:@SECLEVEL=0")

    # Enable legacy server connect / unsafe legacy renegotiation to talk to unpatched servers.
    # When ssl.OP_LEGACY_SERVER_CONNECT isn't available, 0x4 is the known OpenSSL flag value.
    # 
    legacy_flag = getattr(ssl, "OP_LEGACY_SERVER_CONNECT", 0x4)
    ctx.options |= legacy_flag

    return ctx


def _build_base_url(ip: str, scheme: str, port: Optional[int]) -> str:
    # ip may include scheme already
    m = re.match(r"^(https?)://(.+)$", ip.strip(), flags=re.I)
    if m:
        scheme = m.group(1).lower()
        host = m.group(2).split("/")[0]
    else:
        host = ip.strip()

    if port:
        return f"{scheme}://{host}:{port}"
    return f"{scheme}://{host}"


def _extract_csb_from_text(text: str) -> Optional[str]:
    # Matches /csb439a98b/ in Location or URLs
    m = re.search(r"/(csb[0-9a-zA-Z]+)/", text or "")
    return m.group(1) if m else None


def _get_csb_prefix(sess: requests.Session, base_url: str, timeout: int, verify: bool) -> str:
    # First try without redirects so we can read Location header (common SG200 behavior)
    r = sess.get(base_url + "/", allow_redirects=False, timeout=timeout, verify=verify)
    if 300 <= r.status_code < 400:
        csb = _extract_csb_from_text(r.headers.get("Location", ""))
        if csb:
            return csb

    # Follow redirects and parse final URL
    r2 = sess.get(base_url + "/", allow_redirects=True, timeout=timeout, verify=verify)
    csb2 = _extract_csb_from_text(r2.url)
    return csb2 or ""


def _find_login_form(html: str) -> Optional[Tuple[str, Dict[str, str], str, str]]:
    """
    Find a login form (best-effort) and return:
      (action, hidden_fields, username_field_name, password_field_name)
    """
    soup = BeautifulSoup(html, "html.parser")

    for form in soup.find_all("form"):
        pwd_inp = form.find("input", {"type": "password"})
        if not pwd_inp:
            continue

        action = form.get("action") or ""
        inputs = form.find_all("input")

        hidden: Dict[str, str] = {}
        pass_name = pwd_inp.get("name") or "password"
        user_name = None

        # collect hidden fields
        for inp in inputs:
            name = inp.get("name")
            if not name:
                continue
            itype = (inp.get("type") or "").lower()
            val = inp.get("value") or ""
            if itype == "hidden":
                hidden[name] = val

        # locate username input
        text_inputs = []
        for inp in inputs:
            itype = (inp.get("type") or "").lower()
            if itype in ("text", "email", ""):
                nm = inp.get("name") or ""
                ident = (inp.get("id") or "")
                if nm:
                    text_inputs.append((nm, (nm + " " + ident).lower()))

        for nm, nm_l in text_inputs:
            if any(k in nm_l for k in ("user", "login", "name")):
                user_name = nm
                break
        if not user_name and text_inputs:
            user_name = text_inputs[0][0]

        if user_name:
            return action, hidden, user_name, pass_name

    return None


def _login_if_needed(
    sess: requests.Session,
    landing_url: str,
    username: str,
    password: str,
    timeout: int,
    verify: bool,
) -> None:
    r = sess.get(landing_url, timeout=timeout, verify=verify, allow_redirects=True)
    if r.status_code >= 400:
        return

    if 'type="password"' not in r.text.lower():
        return  # likely already authenticated

    parsed = _find_login_form(r.text)
    if not parsed:
        return

    action, hidden_fields, user_field, pass_field = parsed
    post_url = urljoin(r.url, action) if action else r.url

    data = dict(hidden_fields)
    data[user_field] = username
    data[pass_field] = password

    sess.post(post_url, data=data, timeout=timeout, verify=verify, allow_redirects=True)


def fetch_mac_table(
    switch_ip: str,
    username: str,
    password: str,
    *,
    scheme: str = "https",                 # option2 default
    port: Optional[int] = 443,             # option2 default
    ignore_https_errors: bool = True,
    timeout: int = DEFAULT_TIMEOUT,
) -> List[Dict]:
    """
    Returns list[dict] entries: {switch_ip, vlan, mac, port_index}
    """
    scheme_eff = (scheme or "https").lower()
    if scheme_eff not in ("https", "http"):
        raise ValueError("scheme must be 'https' or 'http'")

    base_url = _build_base_url(switch_ip, scheme_eff, port if scheme_eff == "https" else port)

    verify = not ignore_https_errors

    ctx = _make_sg200_legacy_ssl_context(ignore_cert_errors=ignore_https_errors)

    sess = requests.Session()
    sess.mount("https://", SSLContextAdapter(ctx))

    attempt_errors: List[str] = []

    try:
        csb = _get_csb_prefix(sess, base_url, timeout, verify)
    except Exception as e:
        attempt_errors.append(f"csb discovery: {e}")
        raise RuntimeError(
            f"SG200 fetch_mac_table failed for {switch_ip}. Attempts:\n- " + "\n- ".join(attempt_errors)
        ) from e

    landing = base_url + (f"/{csb}/" if csb else "/")

    try:
        _login_if_needed(sess, landing, username, password, timeout, verify)
    except Exception as e:
        attempt_errors.append(f"login: {e}")
        # continue; sometimes session is already authenticated or login page differs

    mac_path = "Adrs_tbl/bridg_frdData_dynamicAddress_m.htm"
    mac_url = f"{base_url}/{csb}/{mac_path}" if csb else f"{base_url}/{mac_path}"

    try:
        r = sess.get(mac_url, timeout=timeout, verify=verify, allow_redirects=True)
        r.raise_for_status()
    except Exception as e:
        attempt_errors.append(f"mac table GET: {e}")
        raise RuntimeError(
            f"SG200 fetch_mac_table failed for {switch_ip}. Attempts:\n- " + "\n- ".join(attempt_errors)
        ) from e

    if "dot1qTpFdbAddress$repeat" not in r.text:
        # One retry after revisiting landing (sometimes auth redirect)
        try:
            sess.get(landing, timeout=timeout, verify=verify, allow_redirects=True)
            r = sess.get(mac_url, timeout=timeout, verify=verify, allow_redirects=True)
            r.raise_for_status()
        except Exception as e:
            attempt_errors.append(f"mac table retry: {e}")
            raise RuntimeError(
                f"SG200 fetch_mac_table failed for {switch_ip}. Attempts:\n- " + "\n- ".join(attempt_errors)
            ) from e

    if "dot1qTpFdbAddress$repeat" not in r.text:
        raise RuntimeError(
            "MAC table markers not found; auth likely failed or firmware page differs."
        )

    entries = _parse_dynamic_mac_table(r.text, switch_ip=switch_ip)
    return [asdict(e) for e in entries]


if __name__ == "__main__":
    import json
    import sys

    if len(sys.argv) < 4:
        print("Usage: python sg200_client.py <ip> <user> <pass> [https|http]")
        sys.exit(2)

    ip = sys.argv[1]
    user = sys.argv[2]
    pwd = sys.argv[3]
    sch = sys.argv[4] if len(sys.argv) >= 5 else "https"

    rows = fetch_mac_table(ip, user, pwd, scheme=sch, ignore_https_errors=True)
    print(json.dumps({"switch_ip": ip, "entries": rows}, indent=2))
