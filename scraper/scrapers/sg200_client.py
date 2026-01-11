#!/usr/bin/env python3
"""
Library to scrape data from a Cisco SG200.

Public API:
    fetch_mac_table(switch_ip, username, password) -> List[dict]
    fetch_system_summary(switch_ip, username, password) -> dict
"""

import re
from dataclasses import dataclass, asdict
<<<<<<< HEAD
from typing import Dict, List, Optional, Tuple
=======
from typing import Dict, List, Optional
>>>>>>> origin/main

from bs4 import BeautifulSoup
from playwright.sync_api import sync_playwright, TimeoutError as PlaywrightTimeoutError

NAV_TIMEOUT_MS = 15000  # 15 seconds


@dataclass
class MacEntry:
    vlan: int
    mac: str
    port_index: int
    switch_ip: str


def _perform_login(page, username: str, password: str) -> None:
    """
    Find a frame with a password field, fill username/password, submit.
    """
    login_frame = None
    for frame in page.frames:
        try:
            pw = frame.query_selector("input[type='password']")
        except PlaywrightTimeoutError:
            pw = None
        if pw is not None:
            login_frame = frame
            break

    if login_frame is None:
        # Already logged in or different firmware behavior
        return

    pw = login_frame.query_selector("input[type='password']")
    if pw is None:
        raise RuntimeError("Password field not found in login frame")

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

    page.wait_for_timeout(4000)


def _detect_csb_prefix(page) -> str:
    """
    After login, inspect frame URLs to find /csbXXXXXX/.
    """
    pattern = re.compile(r"/(csb[0-9a-fA-F]+)/")

    # Check frames first
    for frame in page.frames:
        m = pattern.search(frame.url)
        if m:
            return m.group(1)

    # Fallback to top-level page URL
    m = pattern.search(page.url)
    if m:
        return m.group(1)

    raise RuntimeError("Could not detect csbXXXXXX prefix after login")


def _normalize_label(text: str) -> str:
    return " ".join(text.replace("\xa0", " ").strip().split()).rstrip(":")


def _parse_dynamic_mac_table(html: str, switch_ip: str) -> List[MacEntry]:
    """
    Parse VLAN / MAC / port entries from the Dynamic MAC page HTML.

    Uses hidden INPUTs:
      - dot1qFdbId$repeat?N          (VLAN)
      - dot1qTpFdbAddress$repeat?N   (MAC as hex string)
      - dot1qTpFdbPort$repeat?N      (port index)
    """
    soup = BeautifulSoup(html, "html.parser")
    inputs = soup.find_all("input")

    vlan_by_idx: Dict[str, int] = {}
    mac_by_idx: Dict[str, str] = {}
    port_by_idx: Dict[str, int] = {}

    for inp in inputs:
        name = inp.get("name")
        if not name:
            continue
        value = inp.get("value", "")

        if name.startswith("dot1qFdbId$repeat?"):
            idx = name.split("?", 1)[1]
            try:
                vlan_by_idx[idx] = int(value)
            except ValueError:
                continue

        elif name.startswith("dot1qTpFdbAddress$repeat?"):
            idx = name.split("?", 1)[1]
            mac_by_idx[idx] = value.strip()

        elif name.startswith("dot1qTpFdbPort$repeat?"):
            idx = name.split("?", 1)[1]
            try:
                port_by_idx[idx] = int(value)
            except ValueError:
                continue

    entries: List[MacEntry] = []
    for idx in sorted(mac_by_idx.keys(), key=lambda x: int(x)):
        mac_hex = mac_by_idx.get(idx)
        vlan = vlan_by_idx.get(idx)
        port_index = port_by_idx.get(idx)

        if mac_hex is None or vlan is None or port_index is None:
            continue

        mac_hex = mac_hex.lower()
        mac_fmt = ":".join(mac_hex[i:i + 2] for i in range(0, len(mac_hex), 2))
        entries.append(
            MacEntry(
                vlan=vlan,
                mac=mac_fmt,
                port_index=port_index,
                switch_ip=switch_ip,
            )
        )

    return entries


<<<<<<< HEAD
def _parse_port_settings(html: str) -> Dict[int, Dict[str, str]]:
    soup = BeautifulSoup(html, "html.parser")
    mapping: Dict[int, Dict[str, str]] = {}
    table = soup.find("table")
    if not table:
        return mapping

    rows = table.find_all("tr")
    for row in rows:
        cells = [cell.get_text(" ", strip=True) for cell in row.find_all(["td", "th"])]
        if len(cells) < 3:
            continue
        if cells[0].lower().startswith("entry"):
            continue
        try:
            entry_no = int(cells[0])
        except ValueError:
            continue
        interface = cells[1]
        description = cells[2] if len(cells) > 2 else ""
        if interface:
            mapping[entry_no] = {
                "interface": interface,
                "description": description,
            }
    return mapping


=======
>>>>>>> origin/main
def _parse_system_summary(html: str) -> Dict[str, str]:
    soup = BeautifulSoup(html, "html.parser")
    fields = {
        "System Description": "system_description",
        "System Location": "system_location",
        "System Contact": "system_contact",
        "Host Name": "host_name",
        "System Uptime": "system_uptime",
        "Current Time": "current_time",
        "Base MAC Address": "base_mac_address",
        "Jumbo Frames": "jumbo_frames",
        "HTTP Service": "http_service",
        "HTTPS Service": "https_service",
        "Model Description": "model_description",
        "Serial Number": "serial_number",
        "PID VID": "pid_vid",
        "Firmware Version": "firmware_version",
        "Firmware MD5 Checksum": "firmware_md5_checksum",
        "Boot Version": "boot_version",
        "Boot MD5 Checksum": "boot_md5_checksum",
        "Locale": "locale",
        "Language Version": "language_version",
        "Language MD5 Checksum": "language_md5_checksum",
    }

    result: Dict[str, str] = {}
    for cell in soup.find_all(["td", "th"]):
        label = _normalize_label(cell.get_text(" ", strip=True))
        if label in fields:
            value_cell = cell.find_next_sibling(["td", "th"])
            if value_cell:
                value = _normalize_label(value_cell.get_text(" ", strip=True))
                if value:
                    result[fields[label]] = value

    return result


<<<<<<< HEAD
def _find_port_settings_html(page, switch_ip: str, prefix: str) -> Optional[str]:
    candidates = [
        f"http://{switch_ip}/{prefix}/port/Port_settings.htm",
        f"http://{switch_ip}/{prefix}/port/Port_settings_m.htm",
        f"http://{switch_ip}/{prefix}/PortManagement/port_settings.htm",
        f"http://{switch_ip}/{prefix}/PortManagement/port_settings_m.htm",
        f"http://{switch_ip}/{prefix}/PortManagement/port_settings_master.htm",
        f"http://{switch_ip}/{prefix}/PortManagement/port_settings_master_m.htm",
    ]

    home_url = f"http://{switch_ip}/{prefix}/home.htm"
    try:
        page.goto(home_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
    except PlaywrightTimeoutError:
        pass

    try:
        for frame in page.frames:
            try:
                html = frame.content()
            except PlaywrightTimeoutError:
                continue
            if "Port Settings" in html and "Port Setting Table" in html:
                return html
    except Exception:
        pass

    for url in candidates:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            pass
        html = page.content()
        if "Port Settings" in html:
            return html

    return None


=======
>>>>>>> origin/main
def _find_system_summary_html(page, switch_ip: str, prefix: str) -> Optional[str]:
    candidates = [
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/systemSummary.htm",
        f"http://{switch_ip}/{prefix}/sysinfo/system_summary_m.htm",
        f"http://{switch_ip}/{prefix}/Status/system_summary.htm",
        f"http://{switch_ip}/{prefix}/Status/system_summary_m.htm",
    ]

    home_url = f"http://{switch_ip}/{prefix}/home.htm"
    try:
        page.goto(home_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
    except PlaywrightTimeoutError:
        pass

    try:
        for frame in page.frames:
            try:
                html = frame.content()
            except PlaywrightTimeoutError:
                continue
            if "System Summary" in html:
                return html
    except Exception:
        pass

    for url in candidates:
        try:
            page.goto(url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            pass
        html = page.content()
        if "System Summary" in html:
            return html

    return None


def fetch_mac_table(switch_ip: str, username: str, password: str) -> List[dict]:
    """
    Scrape the dynamic MAC table and return a list of dicts:
        [
          {"switch_ip": "192.168.0.221", "vlan": 1, "mac": "aa:bb:...", "port_index": 52},
          ...
        ]
    """
    base_http_url = f"http://{switch_ip}/"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        try:
            page.goto(base_http_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            # Try to continue anyway
            pass

        _perform_login(page, username, password)
        page.wait_for_timeout(3000)

        prefix = _detect_csb_prefix(page)

        dyn_url = f"http://{switch_ip}/{prefix}/Adrs_tbl/bridg_frdData_dynamicAddress_m.htm"
        try:
            page.goto(dyn_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            pass

        html = page.content()
<<<<<<< HEAD
        port_html = _find_port_settings_html(page, switch_ip, prefix)
        browser.close()

    entries = _parse_dynamic_mac_table(html, switch_ip)
    port_map = _parse_port_settings(port_html or "")
    results = []
    for entry in entries:
        data = asdict(entry)
        port_details = port_map.get(entry.port_index)
        if port_details:
            data.update(port_details)
        results.append(data)
    return results
=======
        browser.close()

    entries = _parse_dynamic_mac_table(html, switch_ip)
    return [asdict(e) for e in entries]
>>>>>>> origin/main


def fetch_system_summary(switch_ip: str, username: str, password: str) -> Dict[str, str]:
    """
    Scrape the system summary page and return a dictionary of fields.
    """
    base_http_url = f"http://{switch_ip}/"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context(ignore_https_errors=True)
        page = context.new_page()

        try:
            page.goto(base_http_url, wait_until="domcontentloaded", timeout=NAV_TIMEOUT_MS)
        except PlaywrightTimeoutError:
            pass

        _perform_login(page, username, password)
        page.wait_for_timeout(3000)

        prefix = _detect_csb_prefix(page)
        html = _find_system_summary_html(page, switch_ip, prefix)
        browser.close()

    if not html:
        raise RuntimeError("Unable to locate System Summary page after login.")

    data = _parse_system_summary(html)
    data["switch_ip"] = switch_ip
    return data
