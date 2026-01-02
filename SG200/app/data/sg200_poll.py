import logging
import requests

logging.info("===> Starting Cisco SG200 Poll Script")

logging.debug("Params for SG200 Poll Script:")
logging.debug(params)

response = {}
endpoints = []

collector_host = params.get("connect_ciscosg200_collector_host", "").strip()
collector_port = str(params.get("connect_ciscosg200_collector_port", "")).strip()
collector_proto = params.get("connect_ciscosg200_collector_protocol", "http").strip().lower()
collector_token = params.get("connect_ciscosg200_collector_token", "").strip()
inventory_raw = params.get("connect_ciscosg200_inventory", "").strip()

if not collector_host or not collector_port:
    msg = "Missing collector host or port configuration."
    logging.error("CiscoSG200 Poll: " + msg)
    response["error"] = msg

elif not inventory_raw:
    msg = "No SG200 switches configured (connect_ciscosg200_inventory is empty)."
    logging.error("CiscoSG200 Poll: " + msg)
    response["error"] = msg

else:
    base_url = f"{collector_proto}://{collector_host}:{collector_port}/sg200/mac-table"
    headers = {}
    if collector_token:
        headers["X-Collector-Token"] = collector_token

    # Each line: ip,username,password
    lines = [ln.strip() for ln in inventory_raw.splitlines() if ln.strip()]

    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3:
            logging.error(
                "CiscoSG200 Poll: invalid inventory line "
                "(expected 'ip,username,password'): [%s]",
                line,
            )
            continue

        switch_ip, sg200_username, sg200_password = parts
        if not switch_ip or not sg200_username or not sg200_password:
            logging.error(
                "CiscoSG200 Poll: missing ip/username/password "
                "in inventory line [%s]",
                line,
            )
            continue

        payload = {
            "ip": switch_ip,
            "user": sg200_username,
            "pass": sg200_password,
        }

        try:
            logging.debug(
                "CiscoSG200 Poll: requesting MAC table for switch [%s] "
                "from collector [%s]",
                switch_ip,
                base_url,
            )
            resp = requests.post(base_url, json=payload, headers=headers, timeout=45)
        except requests.exceptions.RequestException as e:
            logging.error(
                "CiscoSG200 Poll: error contacting collector for %s: %s",
                switch_ip,
                e,
            )
            continue

        if resp.status_code != 200:
            logging.error(
                "CiscoSG200 Poll: collector returned HTTP %s for %s (body: %s)",
                resp.status_code,
                switch_ip,
                resp.text[:200],
            )
            continue

        try:
            data = resp.json()
        except ValueError:
            logging.error(
                "CiscoSG200 Poll: invalid JSON from collector for %s: %s",
                switch_ip,
                resp.text[:200],
            )
            continue

        entries = data.get("entries", [])
        if not isinstance(entries, list):
            logging.error(
                "CiscoSG200 Poll: 'entries' is not a list for %s",
                switch_ip,
            )
            continue

        for entry in entries:
            mac = entry.get("mac")
            vlan = entry.get("vlan")
            port_index = entry.get("port_index")

            if not mac:
                continue

            mac_hex = mac.replace(":", "").replace("-", "").lower()

            endpoint = {"mac": mac_hex}
            props = {
                "connect_ciscosg200_switch_ip": switch_ip
            }
            if vlan is not None:
                props["connect_ciscosg200_vlan"] = str(vlan)
            if port_index is not None:
                props["connect_ciscosg200_port_index"] = str(port_index)

            endpoint["properties"] = props
            endpoints.append(endpoint)

    if endpoints:
        response["endpoints"] = endpoints
    else:
        if "error" not in response:
            response["error"] = "No endpoints collected from Cisco SG200 collector."

logging.debug("CiscoSG200 Poll response: %s", response)
logging.info("===> Ending Cisco SG200 Poll Script")
