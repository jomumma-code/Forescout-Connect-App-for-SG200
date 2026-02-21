#!/usr/bin/env python3
"""
Cisco SG200/SG2xx HTTP UI scraper (Playwright).

Supports the classic Small Business frameset UI (csbXXXXXX prefix) used by SG200-26 firmwares.

Public API (used by the collector):
    fetch_mac_table(switch_ip, username, password) -> List[dict]
    fetch_system_summary(switch_ip, username, password) -> Dict[str, str]
    fetch_poll_bundle(switch_ip, username, password) -> Dict[str, object]

Notes:
- Uses Playwright headless Chromium because auth/navigation are JS/frameset based.
- Uses request-first (context.request) for data fetches to reduce timing sensitivity.
- Best-effort logout at end to reduce session accumulation.
"""

import json
import os
import random
import re
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

NAV_TIMEOUT_MS = int(os.environ.get("SG200_NAV_TIMEOUT_MS", "15000"))
DYN_TIMEOUT_MS = int(os.environ.get("SG200_DYN_TIMEOUT_MS", "60000"))
SYS_TIMEOUT_MS = int(os.environ.get("SG200_SYS_TIMEOUT_MS", "60000"))

# Small jitter to avoid repeated "same-tick" races in frameset UIs.
JITTER_MS_MIN = int(os.environ.get("SG200_JITTER_MS_MIN", "300"))
JITTER_MS_MAX = int(os.environ.get("SG200_JITTER_MS_MAX", "900"))


@dataclass
class MacEntry:
    vlan: int
    mac: str
    port_index: int
    switch_ip: str


# -----------------------------
# Shared helpers
# -----------------------------

def _sleep_jitter(page) -> None:
    try:
        page.wait_for_timeout(int(random.uniform(JITTER_MS_MIN, JITTER_MS_MAX)))
    except Exception:
        pass


def _looks_like_login_html(html: str) -> bool:
    if not html:
        return False
    h = html.lower()
    # Broad heuristics: password fields or obvious login markers.
    return ('type="password"' in h) or ("login" in h and "password" in h)


def _perform_login(page, username: str, password: str) -> None:
    """
    Find a frame (or page) with a password field, fill username/password, submit.

    SG200 firmwares commonly render login inside a frame.
    """
    login_frames = []
    try:
        login_frames = list(page.frames)
    except Exception:
        login_frames = []

    # Prefer any frame with a password field; fallback to main frame.
    login_frame = None
    for fr in login_frames:
        try:
            if fr.query_selector("input[type='password']") is not None:
                login_frame = fr
                break
        except Exception:
            continue

    if login_frame is None:
        try:
            if page.query_selector("input[type='password']") is not None:
                login_frame = page.main_frame
        except Exception:
            login_frame = None

    if login_frame is None:
        # Already logged in or different firmware behavior.
        return

    pw = login_frame.query_selector("input[type='password']")
    if pw is None:
        raise RuntimeError("Password field not found on login page")

    user = login_frame.query_selector("input[type='text'], input[type='email']")
    if user is None:
        user = login_frame.query_selector("input:not([type='password'])")
    if user is None:
        raise RuntimeError("Could not locate username field on login page")

    user.fill(username)
    pw.fill(password)

    btn = login_frame.query_selector("input[type='submit'], button, input[type='button']")
    if btn is not None:
        btn.click()
    else:
        pw.press("Enter")

    # Allow UI to transition after auth.
    try:
        page.wait_for_timeout(2500)
    except Exception:
        pass


def _format_mac(mac_hex: str) -> str:
    mac_hex = (mac_hex or "").strip().lower().replace(":", "").replace("-", "")
    if len(mac_hex) == 12 and all(c in "0123456789abcdef" for c in mac_hex):
        return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))
    return mac_hex


def _request_get_text(context, url: str, timeout_ms: int) -> Tuple[Optional[str], Optional[int]]:
    """Return (text, status) or (None, status) on non-ok; never raises."""
    try:
        resp = context.request.get(url, timeout=timeout_ms)
        status = getattr(resp, "status", None)
        if resp and resp.ok:
            return (resp.text() or ""), status
        return None, status
    except Exception:
        return None, None


def _best_effort_logout(context, page, switch_ip: str, prefix: Optional[str]) -> None:
    """
    Attempt to log out (best effort). Never raises.

    - For csb UI: try to discover a logout link in frames, then try common endpoints.    """
    try:
        logout_href = None
        try:
            for fr in page.frames:
                try:
                    html = fr.content()
                except Exception:
                    continue
                m = re.search(
                    r'href=["\']([^"\']*(?:logout|logoff)[^"\']*)["\']',
                    html,
                    re.IGNORECASE,
                )
                if m:
                    logout_href = m.group(1)
                    break
        except Exception:
            logout_href = None

        candidates: List[str] = []
        if logout_href:
            href = logout_href.strip()
            if href.lower().startswith("http"):
                candidates.append(href)
            elif href.startswith("/"):
                candidates.append(f"http://{switch_ip}{href}")
            elif prefix:
                candidates.append(f"http://{switch_ip}/{prefix}/{href.lstrip('/')}")
            else:
                candidates.append(f"http://{switch_ip}/{href.lstrip('/')}")

        if prefix:
            candidates.extend(
                [
                    f"http://{switch_ip}/{prefix}/logout.htm",
                    f"http://{switch_ip}/{prefix}/logout.html",
                    f"http://{switch_ip}/{prefix}/Logout",
                    f"http://{switch_ip}/{prefix}/logoff.htm",
                ]
            )
        # Root-level common candidates (root-style UI)
        candidates.extend(
            [
                f"http://{switch_ip}/logout.htm",
                f"http://{switch_ip}/logout.html",
                f"http://{switch_ip}/Logout",
                f"http://{switch_ip}/logoff.htm",
            ]
        )

        for url in candidates:
            txt, status = _request_get_text(context, url, timeout_ms=5000)
            if txt is not None and (status is None or 200 <= status < 400):
                return
    except Exception:
        return


# -----------------------------
# CSB flavor (csbXXXXXX prefix)
# -----------------------------

def _detect_csb_prefix(page) -> str:
    """After login, inspect frame URLs to find /csbXXXXXX/."""
    pattern = re.compile(r"/(csb[0-9a-fA-F]+)/")

    for frame in page.frames:
        m = pattern.search(frame.url or "")
        if m:
            return m.group(1)

    m = pattern.search(page.url or "")
    if m:
        return m.group(1)

    raise RuntimeError("Could not detect csbXXXXXX prefix after login")


def _parse_portdb_xml(xml_text: str) -> Dict[int, str]:
    """Parse /device/portDB.xml and return a mapping of ifIndex -> portName."""
    out: Dict[int, str] = {}
    if not xml_text:
        return out

    try:
        root = ET.fromstring(xml_text)
    except Exception:
        return out

    for port in root.findall(".//port"):
        try:
            if_index_el = port.find("ifIndex")
            port_name_el = port.find("portName")
            if if_index_el is None or port_name_el is None:
                continue
            if_index = int((if_index_el.text or "").strip())
            port_name = (port_name_el.text or "").strip()
            if port_name:
                out[if_index] = port_name
        except Exception:
            continue
    return out


def _parse_dynamic_mac_table_csb(html: str, switch_ip: str) -> List[MacEntry]:
    """Parse VLAN / MAC / port entries from the Dynamic MAC page HTML (csb flavor)."""
    soup = BeautifulSoup(html or "", "html.parser")
    inputs = soup.find_all("input")

    vlan_by_idx: Dict[str, int] = {}
    mac_by_idx: Dict[str, str] = {}
    port_by_idx: Dict[str, int] = {}

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        value = (inp.get("value") or "").strip()

        if name.startswith("dot1qFdbId$repeat?"):
            idx = name.split("?", 1)[1]
            try:
                vlan_by_idx[idx] = int(value)
            except ValueError:
                continue

        elif name.startswith("dot1qTpFdbAddress$repeat?"):
            idx = name.split("?", 1)[1]
            mac_by_idx[idx] = value

        elif name.startswith("dot1qTpFdbPort$repeat?"):
            idx = name.split("?", 1)[1]
            try:
                port_by_idx[idx] = int(value)
            except ValueError:
                continue

    entries: List[MacEntry] = []
    # idx is numeric string
    for idx in sorted(mac_by_idx.keys(), key=lambda x: int(x) if x.isdigit() else 0):
        mac_hex = mac_by_idx.get(idx)
        vlan = vlan_by_idx.get(idx)
        port_index = port_by_idx.get(idx)

        if not mac_hex or vlan is None or port_index is None:
            continue

        entries.append(
            MacEntry(
                vlan=vlan,
                mac=_format_mac(mac_hex),
                port_index=port_index,
                switch_ip=switch_ip,
            )
        )

    return entries


def _looks_like_system_summary_csb(html: str) -> bool:
    if not html:
        return False
    return (
        ("rlPhdUnitGenParamSerialNum$repeat?1" in html)
        or ("rlPhdUnitGenParamSwVer$repeat?1" in html)
        or ("rndImage1Version$repeat?1" in html)
        or ("rndImage2Version$repeat?1" in html)
        or ("sysDescr$scalar" in html)
        or ("sysName" in html and "sysDescr" in html)
    )


def _get_input_value(soup: BeautifulSoup, name: str) -> Optional[str]:
    inp = soup.find("input", {"name": name})
    if not inp:
        return None
    val = inp.get("value")
    if val is None:
        return None
    val = str(val).strip()
    return val if val != "" else None


def _extract_default_value(vt_value: str) -> Optional[str]:
    if not vt_value:
        return None
    m = re.search(r"Default value=([^;]+)", vt_value)
    if not m:
        return None
    return m.group(1).strip() or None


def _parse_system_summary_csb(html: str) -> Dict[str, str]:
    """Parse csb system summary using hidden inputs."""
    soup = BeautifulSoup(html or "", "html.parser")
    out: Dict[str, str] = {}

    sys_name = _get_input_value(soup, "sysName")
    if sys_name:
        out["host_name"] = sys_name.strip()

    model = (
        _get_input_value(soup, "sysDescr$scalar")
        or _get_input_value(soup, "sysDescr")
        or _get_input_value(soup, "rlPhdUnitGenParamDeviceDescr$repeat?1")
    )
    if model:
        out["model_description"] = " ".join(model.replace("\xa0", " ").split())

    fw = (
        _get_input_value(soup, "rndImage1Version$repeat?1")
        or _get_input_value(soup, "rndImage2Version$repeat?1")
        or _get_input_value(soup, "rlPhdUnitGenParamSwVer$repeat?1")
    )
    if fw:
        out["firmware_version"] = fw.strip()

    serial = _get_input_value(soup, "rlPhdUnitGenParamSerialNum$repeat?1") or _extract_default_value(
        _get_input_value(soup, "rlPhdUnitGenParamSerialNum$VT") or ""
    )
    if serial:
        out["serial_number"] = serial.strip()

    return out


def _find_system_summary_html_requestfirst(context, switch_ip: str, prefix: str) -> Optional[str]:
    """Fetch System Summary HTML via authenticated request context (less timing-sensitive than page.goto)."""
    candidates = [
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_Sx200_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_Sx200.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_information_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_information.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/systemSummary.htm",
        f"http://{switch_ip}/{prefix}/Status/system_summary_m.htm",
        f"http://{switch_ip}/{prefix}/Status/system_summary.htm",
    ]

    for url in candidates:
        html, _ = _request_get_text(context, url, timeout_ms=SYS_TIMEOUT_MS)
        if not html:
            continue
        if _looks_like_system_summary_csb(html):
            return html
        if _looks_like_login_html(html):
            return html
    return None


def _find_system_summary_html_page(page, switch_ip: str, prefix: str) -> Optional[str]:
    """Fallback: use page navigation to locate System Summary HTML."""
    candidates = [
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_Sx200_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_Sx200.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_general_description.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_information_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_information.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary_m.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary.htm",
    ]

    # Try visiting home to populate frames.
    try:
        page.goto(f"http://{switch_ip}/{prefix}/home.htm", wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
    except Exception:
        pass

    # Check already-loaded frames.
    try:
        for fr in page.frames:
            try:
                html = fr.content()
            except Exception:
                continue
            if _looks_like_system_summary_csb(html):
                return html
    except Exception:
        pass

    # Try direct candidate URLs.
    for url in candidates:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except Exception:
            continue

        try:
            html = page.content()
        except Exception:
            html = ""

        if _looks_like_system_summary_csb(html):
            return html
    return None


def _fetch_system_summary_csb(context, page, switch_ip: str, prefix: str, username: str, password: str) -> Dict[str, str]:
    """
    Robust csb system summary fetch:
      1) request-first
      2) if login bounce detected, re-login once and retry request-first
      3) fallback to page navigation
    """
    html = _find_system_summary_html_requestfirst(context, switch_ip, prefix)
    if html and _looks_like_login_html(html):
        _perform_login(page, username, password)
        _sleep_jitter(page)
        html = _find_system_summary_html_requestfirst(context, switch_ip, prefix)

    if not html or not _looks_like_system_summary_csb(html):
        html2 = _find_system_summary_html_page(page, switch_ip, prefix)
        if html2:
            html = html2

    if not html or not _looks_like_system_summary_csb(html):
        raise RuntimeError("Unable to locate System Summary page after login.")

    return _parse_system_summary_csb(html)


def _fetch_mac_table_csb(context, page, switch_ip: str, prefix: str, username: str, password: str) -> List[Dict[str, object]]:
    """
    Fetch csb dynamic MAC table with port-name normalization via portDB.xml.
    Retries once on login-bounce.
    """
    # portDB mapping
    port_name_by_ifindex: Dict[int, str] = {}
    try:
        portdb_url = f"http://{switch_ip}/{prefix}/device/portDB.xml?Filter:(ifOperStatus!=6)"
        xml_text, _ = _request_get_text(context, portdb_url, timeout_ms=NAV_TIMEOUT_MS)
        if xml_text:
            port_name_by_ifindex = _parse_portdb_xml(xml_text)
    except Exception:
        port_name_by_ifindex = {}

    dyn_url = f"http://{switch_ip}/{prefix}/Adrs_tbl/bridg_frdData_dynamicAddress_m.htm"

    dyn_html, status = _request_get_text(context, dyn_url, timeout_ms=DYN_TIMEOUT_MS)
    if not dyn_html:
        # fallback to browser navigation
        try:
            page.goto(dyn_url, wait_until="load", timeout=DYN_TIMEOUT_MS)
            dyn_html = page.content()
        except PlaywrightTimeoutError as exc:
            raise RuntimeError(f"Timeout loading Dynamic Addresses page within {int(DYN_TIMEOUT_MS/1000)}s") from exc

    entries = _parse_dynamic_mac_table_csb(dyn_html or "", switch_ip)

    # Retry once if bounced to login.
    if (not entries) and _looks_like_login_html(dyn_html or ""):
        _perform_login(page, username, password)
        _sleep_jitter(page)

        dyn_html2, _ = _request_get_text(context, dyn_url, timeout_ms=DYN_TIMEOUT_MS)
        if not dyn_html2:
            try:
                page.goto(dyn_url, wait_until="load", timeout=DYN_TIMEOUT_MS)
                dyn_html2 = page.content()
            except PlaywrightTimeoutError as exc:
                raise RuntimeError(f"Timeout loading Dynamic Addresses page within {int(DYN_TIMEOUT_MS/1000)}s") from exc

        entries = _parse_dynamic_mac_table_csb(dyn_html2 or "", switch_ip)

        if (not entries) and _looks_like_login_html(dyn_html2 or ""):
            raise RuntimeError("Session not authenticated when fetching Dynamic Addresses (redirected to login).")

    out_entries: List[Dict[str, object]] = []
    for e in entries:
        raw = e.port_index
        name = port_name_by_ifindex.get(raw)
        port_index = (name or str(raw)).strip()
        out_entries.append(
            {
                "switch_ip": e.switch_ip,
                "vlan": e.vlan,
                "mac": e.mac,
                "port_index": port_index,
            }
        )
    return out_entries


# -----------------------------
# Public API
# -----------------------------

def fetch_poll_bundle(switch_ip: str, username: str, password: str) -> Dict[str, object]:
    """
    SG200-26 (CSB frameset UI) poll bundle over HTTP only.

    Collects:
      - System Summary
      - Dynamic MAC Address Table (with port-name normalization via portDB.xml)

    Returns:
        {
          "switch_ip": "...",
          "system_summary": {...},
          "mac_table": {"switch_ip": "...", "entries": [...]}
        }
    """
    base_http_url = f"http://{switch_ip}/"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        # HTTP-only target; no HTTPS context needed.
        context = browser.new_context()
        page = context.new_page()

        prefix: Optional[str] = None
        try:
            try:
                page.goto(base_http_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
            except PlaywrightTimeoutError:
                pass

            _perform_login(page, username, password)
            _sleep_jitter(page)

            # SG200-26 support: require csbXXXXXX prefix
            prefix = _detect_csb_prefix(page)

            # System summary (fail-soft: do not kill the whole poll if summary is flaky)
            try:
                system_summary = _fetch_system_summary_csb(context, page, switch_ip, prefix, username, password)
            except Exception:
                system_summary = {}
            system_summary["switch_ip"] = switch_ip

            mac_entries = _fetch_mac_table_csb(context, page, switch_ip, prefix, username, password)

            _best_effort_logout(context, page, switch_ip, prefix)

            return {
                "switch_ip": switch_ip,
                "system_summary": system_summary,
                "mac_table": {"switch_ip": switch_ip, "entries": mac_entries},
            }

        except Exception as exc:
            # Make it obvious this module is CSB-only.
            raise RuntimeError(f"SG200-26 poll bundle failed over HTTP (csb UI): {exc}") from exc
        finally:
            try:
                browser.close()
            except Exception:
                pass



def fetch_mac_table(switch_ip: str, username: str, password: str) -> List[dict]:
    """
    Scrape the dynamic MAC table and return:
        [{"switch_ip": "...", "vlan": 1, "mac": "aa:bb:...", "port_index": "gi1"}, ...]
    """
    bundle = fetch_poll_bundle(switch_ip, username, password)
    entries = (bundle.get("mac_table") or {}).get("entries") or []
    return entries if isinstance(entries, list) else []


def fetch_system_summary(switch_ip: str, username: str, password: str) -> Dict[str, str]:
    """Scrape system summary and return a dict. Raises if we can't parse anything."""
    bundle = fetch_poll_bundle(switch_ip, username, password)
    summary = bundle.get("system_summary") or {}
    if not isinstance(summary, dict) or not summary:
        raise RuntimeError("System summary is empty or invalid.")
    return summary
