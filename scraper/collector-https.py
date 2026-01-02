#!/usr/bin/env python3
"""
collector.py

Shared external collector for:
- Cisco SG200 MAC table:        POST /sg200/mac-table
- Netgear WNDR4500 access list: POST /netgear/access-control

Notes (security):
- Do NOT log request bodies (contain credentials).
- Restrict network access to this service (ACL/firewall).
"""

import logging
import os
from typing import Any, Dict, Optional

from flask import Flask, jsonify, request

from sg200_client import fetch_mac_table
from netgear_client import fetch_netgear_devices

app = Flask(__name__)


def _log_level_from_env() -> int:
    lvl = (os.environ.get("COLLECTOR_LOG_LEVEL") or "INFO").upper()
    return getattr(logging, lvl, logging.INFO)


logging.basicConfig(
    level=_log_level_from_env(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("collector")


def _json_body() -> Dict[str, Any]:
    # silent=True prevents exceptions on invalid JSON
    return request.get_json(silent=True) or {}


def _as_bool(v: Any, default: bool = False) -> bool:
    if v is None:
        return default
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        return v.strip().lower() in ("1", "true", "yes", "y", "on")
    return default


def _as_int(v: Any, default: Optional[int] = None) -> Optional[int]:
    if v is None or v == "":
        return default
    try:
        return int(v)
    except Exception:
        return default


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"}), 200


@app.route("/sg200/mac-table", methods=["POST"])
def sg200_mac_table():
    """
    POST /sg200/mac-table
    JSON body (required):
      {
        "ip": "192.168.0.221",
        "user": "cisco",
        "pass": "cisco"
      }

    Optional HTTPS controls:
      {
        "scheme": "https",               # or "http"
        "port": 443,                     # optional
        "prefer_https": true,            # if scheme omitted
        "ignore_https_errors": true      # accept self-signed/invalid certs
      }
    """
    data = _json_body()

    switch_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not switch_ip or not username or not password:
        return jsonify({"error": "ip, user, and pass fields are required in JSON body"}), 400

    logger.info("Request for SG200 MAC table from %s", switch_ip)

    try:
        # IMPORTANT: pass through HTTPS controls so caller can force https-only.
        entries = fetch_mac_table(
            switch_ip,
            username,
            password,
            scheme=data.get("scheme") or "https",
            port=_as_int(data.get("port"), 443),
            ignore_https_errors=_as_bool(data.get("ignore_https_errors"), True),
            # fetch_mac_table signature supports only these in the Option-2 requests-based client.
        )
    except Exception as e:
        logger.exception("Error fetching SG200 MAC table from %s", switch_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify({"switch_ip": switch_ip, "entries": entries}), 200


@app.route("/netgear/access-control", methods=["POST"])
def netgear_access_control():
    """
    POST /netgear/access-control
    JSON body (required):
      {
        "ip": "192.168.1.7",
        "user": "admin",
        "pass": "password"
      }
    """
    data = _json_body()

    router_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not router_ip or not username or not password:
        return jsonify({"error": "ip, user, and pass fields are required in JSON body"}), 400

    logger.info("Request for Netgear access-control devices from %s", router_ip)

    try:
        result = fetch_netgear_devices(router_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching Netgear devices from %s", router_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify(result), 200


if __name__ == "__main__":
    # Bind settings
    host = os.environ.get("COLLECTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("COLLECTOR_PORT", "8080"))

    # Flask dev server is OK for lab; in production prefer gunicorn/uwsgi behind nginx.
    logger.info("Starting collector on %s:%s", host, port)
    app.run(host=host, port=port)
