import logging
import requests

logging.info("===> Starting Netgear WNDR4500 Access Control Poll Script")

logging.debug("Params for Netgear WNDR4500 Poll Script:")
logging.debug(params)

response = {}
endpoints = []

collector_host = params.get("connect_netgearwndr4500_collector_host", "").strip()
collector_port = str(params.get("connect_netgearwndr4500_collector_port", "")).strip()
collector_proto = params.get("connect_netgearwndr4500_collector_protocol", "http").strip().lower()
inventory_raw = params.get("connect_netgearwndr4500_inventory", "").strip()

if not collector_host or not collector_port:
    msg = "Missing collector host or port configuration."
    logging.error("NetgearWNDR4500 Poll: " + msg)
    response["error"] = msg
elif not inventory_raw:
    msg = "Netgear router inventory is empty."
    logging.error("NetgearWNDR4500 Poll: " + msg)
    response["error"] = msg
else:
    base_url = f"{collector_proto}://{collector_host}:{collector_port}/netgear/access-control"

    # Parse inventory: one router per line: ip,username,password
    lines = [ln.strip() for ln in inventory_raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    for line in lines:
        parts = [p.strip() for p in line.split(",")]
        if len(parts) != 3:
            logging.error(
                "NetgearWNDR4500 Poll: invalid inventory line (expected 'ip,username,password'). "
                "Skipping line."
            )
            continue

        router_ip, ng_username, ng_password = parts
        if not router_ip or not ng_username or not ng_password:
            logging.error(
                "NetgearWNDR4500 Poll: missing ip/username/password in inventory entry for router [%s].",
                router_ip or "<unknown>",
            )
            continue

        payload = {
            "ip": router_ip,
            "user": ng_username,
            "pass": ng_password
        }

        try:
            logging.debug(
                "NetgearWNDR4500 Poll: requesting access control list for router [%s] from collector [%s]",
                router_ip,
                base_url,
            )
            resp = requests.post(base_url, json=payload, timeout=45)
        except requests.exceptions.RequestException as e:
            logging.error(
                "NetgearWNDR4500 Poll: error contacting collector for router %s: %s",
                router_ip,
                e,
            )
            # Continue to other routers
            continue

        if resp.status_code != 200:
            logging.error(
                "NetgearWNDR4500 Poll: collector returned HTTP %s for router %s (body: %s)",
                resp.status_code,
                router_ip,
                resp.text[:200],
            )
            continue

        try:
            data = resp.json()
        except ValueError as e:
            logging.error(
                "NetgearWNDR4500 Poll: invalid JSON from collector for router %s: %s",
                router_ip,
                e,
            )
            continue

        entries = data.get("entries", [])
        if not isinstance(entries, list):
            logging.error(
                "NetgearWNDR4500 Poll: collector JSON for router %s missing 'entries' list.",
                router_ip,
            )
            continue

        returned_router_ip = data.get("router_ip", router_ip)

        for entry in entries:
            mac = entry.get("mac")
            if not mac:
                continue

            mac_hex = mac.replace(":", "").replace("-", "").lower()
            if len(mac_hex) != 12:
                logging.debug(
                    "NetgearWNDR4500 Poll: skipping malformed MAC [%s] from router [%s]",
                    mac,
                    returned_router_ip,
                )
                continue

            endpoint = {"mac": mac_hex}
            props = {
                "connect_netgearwndr4500_router_ip": returned_router_ip
            }

            status = entry.get("status")
            if status is not None:
                props["connect_netgearwndr4500_status"] = str(status)

            conn_type = entry.get("conn_type")
            if conn_type is not None:
                props["connect_netgearwndr4500_conn_type"] = str(conn_type)

            name = entry.get("name")
            if name:
                props["connect_netgearwndr4500_device_name"] = str(name)

            endpoint["properties"] = props
            endpoints.append(endpoint)

if endpoints:
    response["endpoints"] = endpoints
else:
    if "error" not in response:
        response["error"] = "No endpoints collected from Netgear collector."

logging.debug("NetgearWNDR4500 Poll response: %s", response)
logging.info("===> Ending Netgear WNDR4500 Access Control Poll Script")
