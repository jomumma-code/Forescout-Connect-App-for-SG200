#!/usr/bin/env python3
"""
Library to retrieve access control device list from a Netgear WNDR4500v3 router.

Public API:
    fetch_netgear_devices(router_ip, username, password) -> dict

Returned dictionary format:
    {
        "router_ip": "192.168.1.7",
        "entries": [
            {
                "router_ip": "192.168.1.7",
                "ip": "192.168.1.199",
                "mac": "00:0c:29:b2:94:c0",
                "status": "Allowed",
                "conn_type": "wired",
                "name": "DESKTOP-EXAMPLE"
            },
            ...
        ]
    }
"""

import html
import re
from dataclasses import dataclass, asdict
from typing import Dict, List, Optional

import requests
from requests.auth import HTTPBasicAuth


# Regexes to match the embedded JavaScript variables in AccessControl_show.htm
DEVICE_RE = re.compile(
    r'var\s+access_control_device(\d+)\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)

NAME_RE = re.compile(
    r'var\s+access_control_device_name(\d+)\s*=\s*"([^"]*)"',
    re.IGNORECASE,
)


@dataclass
class NetgearDevice:
    router_ip: str
    ip: str
    mac: str
    status: str
    conn_type: str
    name: Optional[str] = None


def _normalize_mac(raw_mac: str) -> Optional[str]:
    """
    Normalize MAC into lower-case colon-delimited form.

    Returns:
        normalized MAC string like "aa:bb:cc:dd:ee:ff", or None if invalid.
    """
    if not raw_mac:
        return None

    mac_hex = raw_mac.replace(":", "").replace("-", "").strip().lower()
    if len(mac_hex) != 12 or not all(c in "0123456789abcdef" for c in mac_hex):
        return None

    return ":".join(mac_hex[i:i + 2] for i in range(0, 12, 2))


def parse_access_control_html(router_ip: str, html_text: str) -> List[Dict[str, str]]:
    """
    Parse the AccessControl_show.htm page and extract device entries.

    Args:
        router_ip: IP address of the Netgear router.
        html_text: Raw HTML text returned by the router.

    Returns:
        List of dictionaries, one per device.
    """
    devices: Dict[int, NetgearDevice] = {}

    # Parse core device rows
    for match in DEVICE_RE.finditer(html_text):
        idx = int(match.group(1))
        raw_value = match.group(2)
        parts = raw_value.split("*")

        # Expected: status*ip*mac*conn_type
        if len(parts) < 3:
            continue

        status = parts[0].strip()
        ip = parts[1].strip()
        mac = parts[2].strip()
        conn_type = parts[3].strip() if len(parts) > 3 else ""

        norm_mac = _normalize_mac(mac)
        if not norm_mac:
            # Skip malformed MACs rather than raising.
            continue

        devices[idx] = NetgearDevice(
            router_ip=router_ip,
            ip=ip,
            mac=norm_mac,
            status=status,
            conn_type=conn_type,
        )

    # Parse friendly names
    for match in NAME_RE.finditer(html_text):
        idx = int(match.group(1))
        raw_name = match.group(2) or ""
        if idx not in devices:
            continue

        # Unescape HTML entities and strip angle brackets used for "<Unknown>".
        name = html.unescape(raw_name).strip()
        name = name.strip("<>") or None
        if name:
            devices[idx].name = name

    return [asdict(d) for d in devices.values()]


def fetch_netgear_devices(
    router_ip: str,
    username: str,
    password: str,
    *,
    timeout: int = 10,
) -> Dict[str, object]:
    """
    Retrieve the access control device list from a Netgear WNDR4500v3 router.

    This implementation uses HTTP Basic authentication over HTTP, as observed
    from the device's web UI. If HTTPS is later enabled on the router, this
    function can be adapted to use an https:// URL instead.

    Args:
        router_ip: IP address or hostname of the Netgear router.
        username: Web UI username.
        password: Web UI password.
        timeout: Request timeout in seconds (default 10).

    Returns:
        Dictionary with keys:
            "router_ip": router IP string
            "entries": list of device dictionaries

    Raises:
        requests.RequestException for network/HTTP issues.
    """
    url = f"http://{router_ip}/AccessControl_show.htm"

    # SECURITY: Do not log credentials here.
    resp = requests.get(
        url,
        auth=HTTPBasicAuth(username, password),
        timeout=timeout,
    )
    resp.raise_for_status()

    entries = parse_access_control_html(router_ip, resp.text)

    return {
        "router_ip": router_ip,
        "entries": entries,
    }
