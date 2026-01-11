import importlib
import logging
import os
from typing import Callable, Dict, Optional, Tuple

from flask import Flask, request, jsonify

app = Flask(__name__)

# Basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

ALLOWED_IPS = {
    ip.strip()
    for ip in os.environ.get("SG200_COLLECTOR_ALLOWED_IPS", "").split(",")
    if ip.strip()
}
COLLECTOR_TOKEN = os.environ.get("SG200_COLLECTOR_TOKEN", "").strip()


def _authorize_request() -> Tuple[bool, Optional[Tuple[Dict[str, str], int]]]:
    if ALLOWED_IPS:
        remote = request.remote_addr
        if not remote or remote not in ALLOWED_IPS:
            return False, ({"error": "client IP not allowed"}, 403)

    if COLLECTOR_TOKEN:
        provided = request.headers.get("X-Collector-Token", "").strip()
        if not provided or provided != COLLECTOR_TOKEN:
            return False, ({"error": "missing or invalid collector token"}, 401)

    return True, None


def _load_scraper(scraper_module: str, func_name: str) -> Callable:
    try:
        module = importlib.import_module(f"scrapers.{scraper_module}")
    except ModuleNotFoundError as exc:
        raise RuntimeError(
            f"Scraper module '{scraper_module}' is not available."
        ) from exc

    try:
        return getattr(module, func_name)
    except AttributeError as exc:
        raise RuntimeError(
            f"Scraper module '{scraper_module}' does not export '{func_name}'."
        ) from exc


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
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

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
        fetch_mac_table = _load_scraper("sg200_client", "fetch_mac_table")
        entries = fetch_mac_table(switch_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching SG200 MAC table from %s", switch_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify({"switch_ip": switch_ip, "entries": entries}), 200


@app.route("/sg200/system-summary", methods=["POST"])
def system_summary():
    """
    POST /sg200/system-summary
    JSON body:
        {
          "ip": "192.168.0.221",
          "user": "cisco",
          "pass": "cisco"
        }

    Response:
        {
          "switch_ip": "192.168.0.221",
          "host_name": "GARAGE-SG200",
          "model_description": "...",
          ...
        }
    """
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

    data = request.get_json(silent=True) or {}

    switch_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not switch_ip or not username or not password:
        return (
            jsonify({"error": "ip, user, and pass fields are required in JSON body"}),
            400,
        )

    logger.info("Request for SG200 system summary from %s", switch_ip)

    try:
        fetch_system_summary = _load_scraper("sg200_client", "fetch_system_summary")
        summary = fetch_system_summary(switch_ip, username, password)
    except Exception as e:
        logger.exception("Error fetching SG200 system summary from %s", switch_ip)
        return jsonify({"error": str(e)}), 500

    return jsonify(summary), 200


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
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

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
        fetch_netgear_devices = _load_scraper("netgear_client", "fetch_netgear_devices")
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
