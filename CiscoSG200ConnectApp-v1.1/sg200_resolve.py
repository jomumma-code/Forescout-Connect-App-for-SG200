#!/usr/bin/env python3
"""
Cisco SG200 Connect App - Resolve script (multi-switch).

Resolves SG200 properties for a given endpoint MAC by querying the collector:
  - VLAN / port_index from /sg200/mac-table (match MAC)
  - host_name / serial_number from /sg200/system-summary (best-effort; per switch)

Notes:
- Timeout for collector calls is 45 seconds.
"""

import requests

response = {"properties": {}}

TIMEOUT_SECONDS = 45


def _get_param(key, default=None):
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


def _norm_mac(value):
    if not value:
        return ""
    s = str(value).lower()
    for ch in (":", "-", ".", " ", "\t", "\n", "\r"):
        s = s.replace(ch, "")
    out = "".join([c for c in s if c in "0123456789abcdef"])
    if len(out) == 12:
        return out
    if len(out) > 12 and (len(out) % 2) == 0:
        return out[-12:]
    return ""


def _collector_base():
    host = _get_param("connect_ciscosg200_collector_host", "")
    port = str(_get_param("connect_ciscosg200_collector_port", "8081") or "8081")
    if not host:
        return ""
    return "http://{0}:{1}".format(host, port)


def _switch_candidates():
    candidates = []

    ip1 = _get_param("connect_ciscosg200_switch_ip", "")
    user1 = _get_param("connect_ciscosg200_switch_username", "")
    pw1 = _get_param("connect_ciscosg200_switch_password", "")
    if ip1 and user1 and pw1:
        candidates.append({"idx": 1, "ip": ip1, "user": user1, "pass": pw1})

    for i in range(2, 17):
        ip_i = _get_param("connect_ciscosg200_switch{0}_ip".format(i), "")
        user_i = _get_param("connect_ciscosg200_switch{0}_username".format(i), "")
        pw_i = _get_param("connect_ciscosg200_switch{0}_password".format(i), "")
        if ip_i and user_i and pw_i:
            candidates.append({"idx": i, "ip": ip_i, "user": user_i, "pass": pw_i})

    return candidates


try:
    mac_in = _norm_mac(_get_param("mac", ""))
    if not mac_in:
        response["error"] = "No valid 'mac' provided to resolve script."
    else:
        base = _collector_base()
        if not base:
            response["error"] = "Missing required setting: connect_ciscosg200_collector_host"
        else:
            candidates = _switch_candidates()
            if not candidates:
                response["error"] = "No switches configured."
            else:
                match = None
                chosen = None

                # Find MAC on any configured switch
                for sw in candidates:
                    payload = {"ip": sw["ip"], "user": sw["user"], "pass": sw["pass"]}
                    r = requests.post(
                        base + "/sg200/mac-table",
                        json=payload,
                        headers=_headers(),
                        timeout=TIMEOUT_SECONDS,
                    )
                    if r.status_code != 200:
                        continue
                    data = r.json() if r.text else {}
                    entries = data.get("entries") or []
                    if not isinstance(entries, list):
                        continue

                    for e in entries:
                        if _norm_mac((e or {}).get("mac")) == mac_in:
                            match = e
                            chosen = sw
                            break
                    if match:
                        break

                if not match or not chosen:
                    response["properties"] = {}
                    response["error"] = "No matching SG200 entry found for this MAC on any configured switch."
                else:
                    props = {"connect_ciscosg200_switch_ip": str(chosen["ip"])}
                    if match.get("vlan") is not None:
                        props["connect_ciscosg200_vlan"] = str(match.get("vlan"))
                    if match.get("port_index") is not None:
                        props["connect_ciscosg200_port_index"] = str(match.get("port_index"))

                    # Best-effort system summary for the matched switch
                    try:
                        payload = {"ip": chosen["ip"], "user": chosen["user"], "pass": chosen["pass"]}
                        r2 = requests.post(
                            base + "/sg200/system-summary",
                            json=payload,
                            headers=_headers(),
                            timeout=TIMEOUT_SECONDS,
                        )
                        if r2.status_code == 200 and r2.text:
                            ss = r2.json()
                            hn = (ss.get("host_name") or "").strip()
                            sn = (ss.get("serial_number") or "").strip()
                            fw = (ss.get("firmware_version") or "").strip()
                            md = (ss.get("model_description") or "").strip()
                            if hn:
                                props["connect_ciscosg200_host_name"] = hn
                            if sn:
                                props["connect_ciscosg200_serial_number"] = sn
                            if fw:
                                props["connect_ciscosg200_firmware_version"] = fw
                            if md:
                                props["connect_ciscosg200_model_description"] = md
                    except Exception:
                        pass

                    response["properties"] = props

except Exception as exc:
    response["error"] = "Resolve execution failed: {0}".format(str(exc))
