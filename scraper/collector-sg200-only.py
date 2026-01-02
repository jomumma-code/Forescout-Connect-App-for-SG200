

import logging
import os

from flask import Flask, request, jsonify
from sg200_client import fetch_mac_table

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
    """
    data = request.get_json(silent=True) or {}

    switch_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not switch_ip or not username or not password:
        return jsonify({"error": "ip, user, and pass fields are required in JSON body"}), 400

    logger.info("Request for MAC table from %s", switch_ip)

    try:
        entries = fetch_mac_table(switch_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching MAC table from %s: %s", switch_ip, e)
        return jsonify({"error": str(e)}), 500

    return jsonify({"switch_ip": switch_ip, "entries": entries})


#!/usr/bin/env python3
"""
SG200 collector API (Flask).

Endpoints:
    GET /sg200/mac-table?ip=...&user=...&pass=...

Response:
    {
      "switch_ip": "192.168.0.221",
      "entries": [
         {"switch_ip": "...", "vlan": 1, "mac": "aa:bb:...", "port_index": 52},
         ...
      ]
    }
"""


if __name__ == "__main__":
    # Use env vars so you can tweak host/port without code changes
    host = os.environ.get("SG200_COLLECTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("SG200_COLLECTOR_PORT", "8080"))
    app.run(host=host, port=port)
