import logging
import os

from flask import Flask, request, jsonify

from sg200_client import fetch_mac_table
from netgear_client import fetch_netgear_devices

app = Flask(__name__)

# Basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/sg200/mac-table", methods=["POST"])
def mac_table():
    """
    POST /sg200/mac-table
    JSON body:
        {
          "ip": "192.168.0.221",
          "user": "cisco",
          "pass": "cisco"
        }

    Response:
        {
          "switch_ip": "192.168.0.221",
          "entries": [
            {"switch_ip": "...", "vlan": 1, "mac": "aa:bb:...", "port_index": 52},
            ...
          ]
        }
    """
    data = request.get_json(silent=True) or {}

    switch_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not switch_ip or not username or not password:
        return (
            jsonify({"error": "ip, user, and pass fields are required in JSON body"}),
            400,
        )

    logger.info("Request for SG200 MAC table from %s", switch_ip)

    try:
        entries = fetch_mac_table(switch_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching SG200 MAC table from %s", switch_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify({"switch_ip": switch_ip, "entries": entries}), 200


@app.route("/netgear/access-control", methods=["POST"])
def netgear_access_control():
    """
    POST /netgear/access-control
    JSON body:
        {
          "ip": "192.168.1.7",
          "user": "admin",
          "pass": "password"
        }

    Response:
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
    data = request.get_json(silent=True) or {}

    router_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not router_ip or not username or not password:
        return (
            jsonify({"error": "ip, user, and pass fields are required in JSON body"}),
            400,
        )

    logger.info("Request for Netgear access-control devices from %s", router_ip)

    try:
        result = fetch_netgear_devices(router_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching Netgear devices from %s", router_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify(result), 200


if __name__ == "__main__":
    # Use env vars so you can tweak host/port without code changes
    host = os.environ.get("SG200_COLLECTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("SG200_COLLECTOR_PORT", "8080"))
    app.run(host=host, port=port)
