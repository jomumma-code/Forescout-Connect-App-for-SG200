#!/usr/bin/env python3
"""
Cisco SG200 Connect App - Poll/Discovery script.

Runs on the schedule configured via the system.conf "host discovery" field.

Outputs:
  response = { "endpoints": [ { "mac": "...", "properties": {...} }, ... ] }
"""

import logging
import re
import requests

# Connect runtime reads this global dict.
response = {"endpoints": []}


def _get_param(key, default=None):
    # `params` is injected by the Connect runtime.
    val = params.get(key, default)  # noqa: F821
    if isinstance(val, str):
        return val.strip()
    return val


def _headers():
    h = {"Content-Type": "application/json"}
    token = _get_param("connect_ciscosg200_collector_token", "")
    if token:
        h["X-Collector-Token"] = token
    return h


def _norm_mac(mac: str) -> str:
    """Normalize MAC into 12-hex format expected by Connect (no separators)."""
    if not mac:
        return ""
    m = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).lower()
    if len(m) == 12:
        return m
    if len(m) > 12 and len(m) % 2 == 0:
        return m[-12:]
    return ""


def _iter_switch_configs(max_switches: int = 16):
    """Yield dicts: {ip, user, pass}. Switch 1 uses unnumbered field IDs."""
    # Switch 1 (legacy field IDs)
    ip = _get_param("connect_ciscosg200_switch_ip", "")
    user = _get_param("connect_ciscosg200_switch_username", "")
    pwd = _get_param("connect_ciscosg200_switch_password", "")
    if ip and user and pwd:
        yield {"ip": ip, "user": user, "pass": pwd}

    # Switch 2..N (numbered field IDs)
    for i in range(2, max_switches + 1):
        ip = _get_param(f"connect_ciscosg200_switch{i}_ip", "")
        user = _get_param(f"connect_ciscosg200_switch{i}_username", "")
        pwd = _get_param(f"connect_ciscosg200_switch{i}_password", "")
        if ip and user and pwd:
            yield {"ip": ip, "user": user, "pass": pwd}


def _extract_entries(resp_json):
    """Best-effort normalization of collector response shape."""
    if not isinstance(resp_json, dict):
        return []
    entries = resp_json.get("entries")
    if isinstance(entries, list):
        return entries
    # Backward compatibility: some collectors may return the list directly.
    if isinstance(resp_json.get("data"), list):
        return resp_json["data"]
    return []


def _get_entry_field(entry: dict, *keys):
    for k in keys:
        if k in entry and entry[k] is not None:
            return entry[k]
    return None


try:
    collector_host = _get_param("connect_ciscosg200_collector_host")
    collector_port = _get_param("connect_ciscosg200_collector_port", "8081")

    if not collector_host or not collector_port:
        response["error"] = "Missing required settings: connect_ciscosg200_collector_host/connect_ciscosg200_collector_port"
    else:
        base = f"http://{collector_host}:{collector_port}"
        switches = list(_iter_switch_configs(16))
        if not switches:
            response["error"] = "No switch credentials configured (need at least one complete IP/username/password set)."
        else:
            endpoints = []
            seen_macs = set()
            errors = []

            for sw in switches:
                payload = {"ip": sw["ip"], "user": sw["user"], "pass": sw["pass"]}
                try:
                    r = requests.post(
                        f"{base}/sg200/mac-table",
                        json=payload,
                        headers=_headers(),
                        timeout=45,
                    )
                    if r.status_code != 200:
                        errors.append(f"{sw['ip']}: /sg200/mac-table HTTP {r.status_code}")
                        continue
                    data = r.json() if r.text else {}

                    # Best-effort system summary (per-switch), stamped onto each discovered endpoint.
                    sw_summary_props = {}
                    try:
                        r2 = requests.post(
                            f"{base}/sg200/system-summary",
                            json=payload,
                            headers=_headers(),
                            timeout=45,
                        )
                        if r2.status_code == 200 and r2.text:
                            ss = r2.json()
                            hn = (ss.get("host_name") or "").strip()
                            sn = (ss.get("serial_number") or "").strip()
                            fw = (ss.get("firmware_version") or "").strip()
                            md = (ss.get("model_description") or "").strip()
                            if hn:
                                sw_summary_props["connect_ciscosg200_host_name"] = hn
                            if sn:
                                sw_summary_props["connect_ciscosg200_serial_number"] = sn
                            if fw:
                                sw_summary_props["connect_ciscosg200_firmware_version"] = fw
                            if md:
                                sw_summary_props["connect_ciscosg200_model_description"] = md
                    except Exception:
                        sw_summary_props = {}

                    for e in _extract_entries(data):
                        if not isinstance(e, dict):
                            continue
                        mac_raw = _get_entry_field(e, "mac", "mac_address", "macAddress")
                        mac = _norm_mac(mac_raw)
                        if not mac:
                            continue

                        # Connect endpoints are keyed by MAC; avoid duplicates across switches.
                        if mac in seen_macs:
                            continue
                        seen_macs.add(mac)

                        vlan = _get_entry_field(e, "vlan", "vlan_id", "vlanId")
                        port_index = _get_entry_field(e, "port_index", "portIndex", "port", "port_id", "portId")

                        props = {"connect_ciscosg200_switch_ip": sw["ip"]}
                        if sw_summary_props:
                            props.update(sw_summary_props)
                        if vlan is not None and str(vlan).strip() != "":
                            props["connect_ciscosg200_vlan"] = str(vlan)
                        if port_index is not None and str(port_index).strip() != "":
                            props["connect_ciscosg200_port_index"] = str(port_index)

                        endpoints.append({"mac": mac, "properties": props})

                except Exception as ex:
                    # Avoid traceback; keep message compact.
                    errors.append(f"{sw['ip']}: request failed ({ex})")

            if endpoints:
                response["endpoints"] = endpoints
                if errors:
                    # Non-fatal; useful in logs/troubleshooting.
                    logging.warning("SG200 poll completed with partial errors: %s", "; ".join(errors))
            else:
                response["error"] = "No endpoints collected from any configured switch."
                if errors:
                    response["error"] += " Errors: " + "; ".join(errors)

except Exception as e:
    response["error"] = f"Poll execution failed: {e}"
