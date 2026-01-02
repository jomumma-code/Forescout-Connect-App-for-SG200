import logging
import requests

logging.info("===> Starting Cisco SG200 Test Script")

logging.debug("Params for SG200 Test Script:")
logging.debug(params)

response = {}

collector_host = params.get("connect_ciscosg200_collector_host", "").strip()
collector_port = str(params.get("connect_ciscosg200_collector_port", "")).strip()
collector_proto = params.get("connect_ciscosg200_collector_protocol", "http").strip().lower()
collector_token = params.get("connect_ciscosg200_collector_token", "").strip()
inventory_raw = params.get("connect_ciscosg200_inventory", "").strip()

if not collector_host or not collector_port:
    msg = "Missing collector host or port configuration."
    logging.error("CiscoSG200 Test: " + msg)
    response["succeeded"] = False
    response["error"] = msg

elif not inventory_raw:
    msg = "No SG200 switches configured (connect_ciscosg200_inventory is empty)."
    logging.error("CiscoSG200 Test: " + msg)
    response["succeeded"] = False
    response["error"] = msg

else:
    # First valid inventory line
    test_line = None
    for ln in inventory_raw.splitlines():
        if ln.strip():
            test_line = ln.strip()
            break

    if not test_line:
        msg = "No valid SG200 entry found in connect_ciscosg200_inventory."
        logging.error("CiscoSG200 Test: " + msg)
        response["succeeded"] = False
        response["error"] = msg
    else:
        parts = [p.strip() for p in test_line.split(",")]
        if len(parts) != 3:
            msg = "First inventory line is invalid. Expect 'ip,username,password'."
            logging.error("CiscoSG200 Test: " + msg)
            response["succeeded"] = False
            response["error"] = msg
        else:
            switch_ip, sg200_username, sg200_password = parts
            base_url = f"{collector_proto}://{collector_host}:{collector_port}/sg200/mac-table"
            headers = {}
            if collector_token:
                headers["X-Collector-Token"] = collector_token

            payload = {
                "ip": switch_ip,
                "user": sg200_username,
                "pass": sg200_password,
            }

            try:
                logging.debug(
                    "CiscoSG200 Test: contacting collector at [%s] for switch [%s]",
                    base_url,
                    switch_ip,
                )
                resp = requests.post(base_url, json=payload, headers=headers, timeout=45)
            except requests.exceptions.RequestException as e:
                msg = f"Error contacting collector: {e}"
                logging.error("CiscoSG200 Test: " + msg)
                response["succeeded"] = False
                response["error"] = msg
            else:
                if resp.status_code != 200:
                    msg = (
                        f"Collector returned HTTP {resp.status_code} for switch "
                        f"{switch_ip}. Body: {resp.text[:200]}"
                    )
                    logging.error("CiscoSG200 Test: " + msg)
                    response["succeeded"] = False
                    response["error"] = msg
                else:
                    try:
                        data = resp.json()
                    except ValueError:
                        msg = "Collector response is not valid JSON."
                        logging.error("CiscoSG200 Test: " + msg)
                        response["succeeded"] = False
                        response["error"] = msg
                    else:
                        entries = data.get("entries", [])
                        if isinstance(entries, list):
                            count = len(entries)
                            msg = (
                                f"Successfully contacted collector and retrieved "
                                f"{count} MAC table entries from SG200 {switch_ip}."
                            )
                            logging.info("CiscoSG200 Test: " + msg)
                            response["succeeded"] = True
                            response["result_msg"] = msg
                        else:
                            msg = "Collector JSON does not contain a list under 'entries'."
                            logging.error("CiscoSG200 Test: " + msg)
                            response["succeeded"] = False
                            response["error"] = msg

logging.debug("CiscoSG200 Test response: %s", response)
logging.info("===> Ending Cisco SG200 Test Script")
