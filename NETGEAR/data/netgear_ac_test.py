import logging
import requests

logging.info("===> Starting Netgear WNDR4500 Access Control Test Script")

logging.debug("Params for Netgear WNDR4500 Test Script:")
logging.debug(params)

response = {}

collector_host = params.get("connect_netgearwndr4500_collector_host", "").strip()
collector_port = str(params.get("connect_netgearwndr4500_collector_port", "")).strip()
collector_proto = params.get("connect_netgearwndr4500_collector_protocol", "http").strip().lower()
inventory_raw = params.get("connect_netgearwndr4500_inventory", "").strip()

if not collector_host or not collector_port:
    msg = "Missing collector host or port configuration."
    logging.error("NetgearWNDR4500 Test: " + msg)
    response["succeeded"] = False
    response["error"] = msg
elif not inventory_raw:
    msg = "Netgear router inventory is empty."
    logging.error("NetgearWNDR4500 Test: " + msg)
    response["succeeded"] = False
    response["error"] = msg
else:
    # Use the first non-empty, non-comment line from the inventory
    lines = [ln.strip() for ln in inventory_raw.splitlines() if ln.strip() and not ln.strip().startswith("#")]

    if not lines:
        msg = "Netgear router inventory does not contain any usable entries."
        logging.error("NetgearWNDR4500 Test: " + msg)
        response["succeeded"] = False
        response["error"] = msg
    else:
        line = lines[0]
        parts = [p.strip() for p in line.split(",")]

        if len(parts) != 3:
            msg = (
                "Invalid Netgear inventory line format. "
                "Expected 'ip,username,password'."
            )
            logging.error("NetgearWNDR4500 Test: " + msg)
            response["succeeded"] = False
            response["error"] = msg
        else:
            router_ip, ng_username, ng_password = parts

            if not router_ip or not ng_username or not ng_password:
                msg = "Missing ip/username/password in Netgear inventory line."
                logging.error("NetgearWNDR4500 Test: " + msg)
                response["succeeded"] = False
                response["error"] = msg
            else:
                base_url = f"{collector_proto}://{collector_host}:{collector_port}/netgear/access-control"

                payload = {
                    "ip": router_ip,
                    "user": ng_username,
                    "pass": ng_password
                }

                try:
                    logging.debug(
                        "NetgearWNDR4500 Test: contacting collector at [%s] for router [%s]",
                        base_url,
                        router_ip,
                    )
                    resp = requests.post(base_url, json=payload, timeout=45)
                except requests.exceptions.RequestException as e:
                    msg = f"Error contacting collector: {e}"
                    logging.error("NetgearWNDR4500 Test: " + msg)
                    response["succeeded"] = False
                    response["error"] = msg
                else:
                    if resp.status_code != 200:
                        msg = (
                            f"Collector returned HTTP {resp.status_code} for router "
                            f"{router_ip}. Body: {resp.text[:200]}"
                        )
                        logging.error("NetgearWNDR4500 Test: " + msg)
                        response["succeeded"] = False
                        response["error"] = msg
                    else:
                        try:
                            data = resp.json()
                        except ValueError as e:
                            msg = f"Collector returned invalid JSON: {e}"
                            logging.error("NetgearWNDR4500 Test: " + msg)
                            response["succeeded"] = False
                            response["error"] = msg
                        else:
                            entries = data.get("entries", [])
                            if isinstance(entries, list):
                                count = len(entries)
                                msg = (
                                    "Successfully contacted collector and retrieved "
                                    f"{count} access control entries from Netgear router {router_ip}."
                                )
                                logging.info("NetgearWNDR4500 Test: " + msg)
                                response["succeeded"] = True
                                response["result_msg"] = msg
                            else:
                                msg = "Collector JSON does not contain a list under 'entries'."
                                logging.error("NetgearWNDR4500 Test: " + msg)
                                response["succeeded"] = False
                                response["error"] = msg

logging.debug("NetgearWNDR4500 Test response: %s", response)
logging.info("===> Ending Netgear WNDR4500 Access Control Test Script")
