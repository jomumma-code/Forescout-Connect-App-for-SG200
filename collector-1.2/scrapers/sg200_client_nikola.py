# scrapers/sg200_client_nikola.py
"""
Nikola-style Cisco SG200 (older UI) scraper.

Key point (from HAR):
- Dynamic MAC table is delivered by AddressTablesDynamicArray.html
- Rows are embedded in JS variable: arraydata_3_1 = [...]
  :contentReference[oaicite:1]{index=1}

This implementation:
- Logs in via POST /nikola_login.html (pwd2 = base64(password))
- Fetches:
    - /AddressTablesDynamicArray.html  -> parses arraydata_*_* into MAC entries
    - /SetupSystemSummary.html        -> parses system summary fields
      (Hostname/Serial/Firmware/System Description present in HTML) :contentReference[oaicite:2]{index=2}

Exports expected by collector.py:
- SG200Error
- fetch_mac_table(ip, user, pass) -> List[Dict]
- fetch_system_summary(ip, user, pass) -> Dict
- fetch_poll_bundle(ip, user, pass) -> Dict
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse

import requests

LOG = logging.getLogger("sg200_client_nikola")

# ---- Exceptions ----

class SG200Error(RuntimeError):
    pass


# ---- Env / tuning ----

def _env_float(name: str, default: float) -> float:
    v = os.getenv(name, "").strip()
    if not v:
        return default
    try:
        return float(v)
    except Exception:
        return default

def _env_bool(name: str, default: bool) -> bool:
    v = os.getenv(name)
    if v is None:
        return default
    return v.strip().lower() in ("1", "true", "yes", "y", "on")

# Defaults tuned for Nikola UI (often HTTP, often self-signed if HTTPS)
TIMEOUT_S = _env_float("SG200_NIKOLA_TIMEOUT_S", 15.0)
VERIFY_TLS = _env_bool("SG200_NIKOLA_VERIFY_TLS", False)

# Scheme order when user passes just an IP/host.
# Nikola HAR commonly shows plain HTTP requests.
SCHEME_ORDER = [s.strip() for s in os.getenv("SG200_NIKOLA_SCHEME_ORDER", "http").split(",") if s.strip()]


# ---- URL helpers ----

def _candidate_base_urls(switch_ip_or_url: str) -> List[str]:
    s = str(switch_ip_or_url or "").strip().rstrip("/")
    if not s:
        raise SG200Error("Empty switch ip/url")

    p = urlparse(s)
    if p.scheme in ("http", "https") and p.netloc:
        return [f"{p.scheme}://{p.netloc}"]

    # Treat as host/ip[:port]
    host = s
    urls: List[str] = []
    for scheme in SCHEME_ORDER:
        if scheme in ("http", "https"):
            urls.append(f"{scheme}://{host}")
    # De-dupe preserving order
    out: List[str] = []
    seen = set()
    for u in urls:
        if u not in seen:
            seen.add(u)
            out.append(u)
    return out

def _join(base_url: str, path: str) -> str:
    base = base_url.rstrip("/")
    if not path.startswith("/"):
        path = "/" + path
    return base + path


# ---- HTTP session / login ----

def _new_session(verify_tls: bool) -> requests.Session:
    sess = requests.Session()
    sess.verify = verify_tls
    sess.headers.update(
        {
            "User-Agent": "sg200-collector/nikola",
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        }
    )
    return sess

def _looks_like_login_page(text: str) -> bool:
    t = (text or "").lower()
    return ("nikola_login" in t) or ("name=\"login\"" in t) or ("pwd2" in t and "usr2" in t)

def _login(sess: requests.Session, base_url: str, username: str, password: str) -> None:
    pwd2 = base64.b64encode(password.encode("utf-8")).decode("ascii")

    form = {
        "uname": username,
        "pwd2": pwd2,
        "language_selector": os.getenv("SG200_NIKOLA_LANGUAGE", "en-US"),
        "err_flag": "0",
        "err_msg": "",
        "passpage": "nikola_main2.html",
        "failpage": "nikola_login.html",
        "submit_flag": "0",
    }

    r = sess.post(
        _join(base_url, "/nikola_login.html"),
        data=form,
        timeout=TIMEOUT_S,
        allow_redirects=True,
    )

    sid = sess.cookies.get("SID")
    if not sid:
        body = (r.text or "")[:5000]
        if _looks_like_login_page(body):
            raise SG200Error("Login failed (login page returned; check credentials).")
        raise SG200Error("Login failed (SID cookie not set).")

    # Optional stabilization
    try:
        sess.get(_join(base_url, "/nikola_main2.html"), timeout=TIMEOUT_S)
    except Exception:
        pass

# ---- System summary ----

_SYS_LABEL_TO_FIELD = {
    # Nikola UI uses "Hostname:" and "System Description:" in SetupSystemSummary.html :contentReference[oaicite:3]{index=3}
    "Hostname": "host_name",
    "Host Name": "host_name",
    "Serial Number": "serial_number",
    "Firmware Version": "firmware_version",
    "System Description": "model_description",  # map to collector's expected semantics
    "Model Description": "model_description",
}

def _extract_by_label(html: str, label: str) -> str:
    # Find "<td ...>Label:</td> ... VALUE="..."" (case-insensitive, dotall)
    # Keep it permissive because the Nikola pages are very loose HTML.
    pat = re.compile(rf"{re.escape(label)}\s*:</td>.*?VALUE\s*=\s*\"([^\"]*)\"", re.I | re.S)
    m = pat.search(html or "")
    return (m.group(1).strip() if m else "")

def fetch_system_summary(switch_ip: str, username: str, password: str) -> Dict[str, Any]:
    last_err: Optional[Exception] = None

    for base_url in _candidate_base_urls(switch_ip):
        sess = _new_session(verify_tls=(VERIFY_TLS if base_url.startswith("https://") else False))
        try:
            _login(sess, base_url, username, password)

            # Try both common placements; HAR shows root paths in some captures.
            html = ""
            for path in ("/SetupSystemSummary.html", "/platform/SetupSystemSummary.html"):
                r = sess.get(_join(base_url, path), timeout=TIMEOUT_S)
                if r.status_code == 200 and (r.text or "").strip():
                    html = r.text
                    if "SetupSystemSummary" in html or "Hostname" in html or "Serial Number" in html:
                        break

            if not html or _looks_like_login_page(html):
                raise SG200Error("System summary fetch returned login page / empty content.")

            out: Dict[str, Any] = {}
            for lab, field in _SYS_LABEL_TO_FIELD.items():
                v = _extract_by_label(html, lab)
                if v and field not in out:
                    out[field] = v

            # Ensure keys exist (collector expects these commonly)
            out.setdefault("host_name", "")
            out.setdefault("serial_number", "")
            out.setdefault("model_description", "")
            out.setdefault("firmware_version", "")
            return out

        except Exception as e:
            last_err = e
            continue
        finally:
            try:
                sess.close()
            except Exception:
                pass

    raise SG200Error(f"System summary failed for all schemes ({SCHEME_ORDER}): {last_err}")


# ---- Dynamic MAC table ----

_ARRAYDATA_RE = re.compile(r"(arraydata_\d+_\d+)\s*=\s*\[(.*?)\];", re.S)

def _parse_dynamic_arraydata(html: str) -> List[Dict[str, Any]]:
    """
    Parse Nikola Dynamic Addresses page (AddressTablesDynamicArray.html).

    Rows in HAR look like:
      ["g2","1","4C:20:B8:E0:58:EC","g2","Learned",""]
    We map to:
      port = row[0] (or row[3], same in observed data)
      vlan_id = row[1]
      mac = row[2]
      learned_type = row[4] (optional)
    """
    m = _ARRAYDATA_RE.search(html or "")
    if not m:
        raise SG200Error("Dynamic MAC table: arraydata_*_* not found in page HTML.")

    var_name = m.group(1)
    inner = m.group(2).strip()

    try:
        rows = json.loads("[" + inner + "]")
    except Exception as e:
        raise SG200Error(f"Dynamic MAC table: failed to JSON-parse {var_name}: {e}") from e

    out: List[Dict[str, Any]] = []
    for row in rows:
        if not isinstance(row, list) or len(row) < 3:
            continue

        port = str(row[0]).strip()
        vlan = str(row[1]).strip()
        mac = str(row[2]).strip()

        if not mac or mac.lower() == "mac address":
            continue

        entry: Dict[str, Any] = {
            "mac": mac,
            "vlan_id": vlan,
            "port": port,
        }

        if len(row) >= 5 and str(row[4]).strip():
            entry["learned_type"] = str(row[4]).strip()

        out.append(entry)

    return out

def fetch_mac_table(switch_ip: str, username: str, password: str) -> List[Dict[str, Any]]:
    last_err: Optional[Exception] = None

    for base_url in _candidate_base_urls(switch_ip):
        sess = _new_session(verify_tls=(VERIFY_TLS if base_url.startswith("https://") else False))
        try:
            _login(sess, base_url, username, password)

            html = ""
            for path in ("/AddressTablesDynamicArray.html", "/platform/AddressTablesDynamicArray.html"):
                r = sess.get(_join(base_url, path), timeout=TIMEOUT_S)
                if r.status_code == 200 and (r.text or "").strip():
                    html = r.text
                    if "arraydata_" in html and "Dynamic Addresses" in html:
                        break

            if not html or _looks_like_login_page(html):
                raise SG200Error("Dynamic MAC table fetch returned login page / empty content.")

            entries = _parse_dynamic_arraydata(html)
            return entries

        except Exception as e:
            last_err = e
            continue
        finally:
            try:
                sess.close()
            except Exception:
                pass

    raise SG200Error(f"MAC table failed for all schemes ({SCHEME_ORDER}): {last_err}")


def fetch_poll_bundle(switch_ip: str, username: str, password: str) -> Dict[str, Any]:
    # Keep it simple and deterministic: separate sessions are fine, but we can reuse one.
    # For now: single session per bundle.
    last_err: Optional[Exception] = None

    for base_url in _candidate_base_urls(switch_ip):
        sess = _new_session(verify_tls=(VERIFY_TLS if base_url.startswith("https://") else False))
        try:
            _login(sess, base_url, username, password)

            # MACs
            dyn_html = ""
            for path in ("/AddressTablesDynamicArray.html", "/platform/AddressTablesDynamicArray.html"):
                r = sess.get(_join(base_url, path), timeout=TIMEOUT_S)
                if r.status_code == 200 and (r.text or "").strip():
                    dyn_html = r.text
                    if "arraydata_" in dyn_html:
                        break
            if not dyn_html or _looks_like_login_page(dyn_html):
                raise SG200Error("Dynamic MAC table fetch returned login page / empty content.")
            mac_entries = _parse_dynamic_arraydata(dyn_html)

            # System summary
            sys_html = ""
            for path in ("/SetupSystemSummary.html", "/platform/SetupSystemSummary.html"):
                r = sess.get(_join(base_url, path), timeout=TIMEOUT_S)
                if r.status_code == 200 and (r.text or "").strip():
                    sys_html = r.text
                    if "Serial Number" in sys_html or "Hostname" in sys_html:
                        break
            if not sys_html or _looks_like_login_page(sys_html):
                raise SG200Error("System summary fetch returned login page / empty content.")

            sys_out: Dict[str, Any] = {}
            for lab, field in _SYS_LABEL_TO_FIELD.items():
                v = _extract_by_label(sys_html, lab)
                if v and field not in sys_out:
                    sys_out[field] = v

            sys_out.setdefault("host_name", "")
            sys_out.setdefault("serial_number", "")
            sys_out.setdefault("model_description", "")
            sys_out.setdefault("firmware_version", "")

            return {
                "switch_ip": str(switch_ip).strip(),
                "mac_table": {"entries": mac_entries},
                "system_summary": sys_out,
            }

        except Exception as e:
            last_err = e
            continue
        finally:
            try:
                sess.close()
            except Exception:
                pass

    raise SG200Error(f"Poll bundle failed for all schemes ({SCHEME_ORDER}): {last_err}")


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    import argparse

    ap = argparse.ArgumentParser()
    ap.add_argument("--ip", required=True)
    ap.add_argument("--user", required=True)
    ap.add_argument("--password", required=True)
    args = ap.parse_args()

    b = fetch_poll_bundle(args.ip, args.user, args.password)
    print(json.dumps(b, indent=2))