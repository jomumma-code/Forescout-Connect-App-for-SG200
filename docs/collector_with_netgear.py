import importlib
import json
import logging
import os
import hmac
import hashlib
from typing import Callable, Dict, Optional, Tuple

from flask import Flask, request, jsonify

app = Flask(__name__)

# Basic logging
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger(__name__)

# --------------------------------------------------------------------
# File-based security config (preferred), with env-var fallback
#
# Create one of:
#   - ./collector_security.json   (same directory as collector.py)
#   - /etc/sg200/collector_security.json
#
# Supported JSON schema:
# {
#   "allowed_ips": ["10.10.10.21", "10.10.10.22", "127.0.0.1"],
#   "token": "cleartext-shared-token"
# }
#
# Or (recommended) store a hash instead of cleartext token:
# {
#   "allowed_ips": "10.10.10.21,10.10.10.22",
#   "token_sha256": "<hex sha256 of token>"
# }
#
# If file is missing, falls back to env vars:
#   SG200_COLLECTOR_ALLOWED_IPS="ip1,ip2"
#   SG200_COLLECTOR_TOKEN="token"
# --------------------------------------------------------------------

_SECURITY_PATHS = [
    os.path.join(os.path.dirname(__file__), "collector_security.json"),
    "/etc/sg200/collector_security.json",
]


def _load_security_config() -> Dict:
    for path in _SECURITY_PATHS:
        try:
            if os.path.exists(path):
                with open(path, "r", encoding="utf-8") as f:
                    cfg = json.load(f) or {}
                logger.info("Loaded collector security config from %s", path)
                if isinstance(cfg, dict):
                    return cfg
                logger.warning("Security config at %s is not a JSON object; ignoring.", path)
        except Exception as e:
            logger.warning("Failed reading security config %s: %s", path, e)
    return {}


_SEC_CFG = _load_security_config()


def _get_allowed_ips_raw() -> str:
    if "allowed_ips" in _SEC_CFG:
        v = _SEC_CFG.get("allowed_ips")
        if isinstance(v, list):
            return ",".join(str(x) for x in v)
        return str(v or "")
    return os.environ.get("SG200_COLLECTOR_ALLOWED_IPS", "")


def _get_token_raw() -> str:
    if "token" in _SEC_CFG:
        return str(_SEC_CFG.get("token") or "").strip()
    return os.environ.get("SG200_COLLECTOR_TOKEN", "").strip()


def _get_token_sha256() -> str:
    if "token_sha256" in _SEC_CFG:
        return str(_SEC_CFG.get("token_sha256") or "").strip().lower()
    return ""


ALLOWED_IPS = {ip.strip() for ip in _get_allowed_ips_raw().split(",") if ip.strip()}
COLLECTOR_TOKEN = _get_token_raw()
COLLECTOR_TOKEN_SHA256 = _get_token_sha256()


def _authorize_request() -> Tuple[bool, Optional[Tuple[Dict[str, str], int]]]:
    # IP allowlist enforcement
    if ALLOWED_IPS:
        remote = request.remote_addr
        if not remote or remote not in ALLOWED_IPS:
            return False, ({"error": "client IP not allowed"}, 403)

    # Token enforcement (hash preferred if present)
    if COLLECTOR_TOKEN_SHA256:
        provided = request.headers.get("X-Collector-Token", "").strip()
        if not provided:
            return False, ({"error": "missing or invalid collector token"}, 401)
        provided_hash = hashlib.sha256(provided.encode("utf-8")).hexdigest().lower()
        if not hmac.compare_digest(provided_hash, COLLECTOR_TOKEN_SHA256):
            return False, ({"error": "missing or invalid collector token"}, 401)

    elif COLLECTOR_TOKEN:
        provided = request.headers.get("X-Collector-Token", "").strip()
        if not provided or not hmac.compare_digest(provided, COLLECTOR_TOKEN):
            return False, ({"error": "missing or invalid collector token"}, 401)

    return True, None


def _load_scraper(scraper_module: str, func_name: str) -> Callable:
    """
    Lazy-load a scraper function.

    Preferred layout: scrapers/<scraper_module>.py (import path 'scrapers.<scraper_module>').
    Fallback layout: <scraper_module>.py alongside collector.py (import path '<scraper_module>').
    """
    module = None
    last_exc: Optional[Exception] = None

    for mod_name in (f"scrapers.{scraper_module}", scraper_module):
        try:
            module = importlib.import_module(mod_name)
            break
        except ModuleNotFoundError as exc:
            last_exc = exc
            module = None

    if module is None:
        raise RuntimeError(f"Scraper module '{scraper_module}' is not available.") from last_exc

    try:
        return getattr(module, func_name)
    except AttributeError as exc:
        raise RuntimeError(
            f"Scraper module '{scraper_module}' does not export '{func_name}'."
        ) from exc


@app.route("/health", methods=["GET"])
def health():
    # Intentionally unauthenticated; protect with network controls if required.
    return jsonify({"status": "ok"})


@app.route("/sg200/mac-table", methods=["POST"])
def mac_table():
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

    # Remove uptime reporting (if present) and guarantee firmware/model fields.
    if isinstance(summary, dict):
        summary.pop("system_uptime_ticks", None)

        fw = summary.get("firmware_version")
        if fw is None or not str(fw).strip():
            summary["firmware_version"] = "N/A"

        md = summary.get("model_description")
        if md is None or not str(md).strip():
            summary["model_description"] = "N/A"

    return jsonify(summary), 200


@app.route("/netgear/access-control", methods=["POST"])
def netgear_access_control():
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

    data = request.get_json(silent=True) or {}

    router_ip = data.get("ip") or data.get("router_ip")
    username = data.get("user") or data.get("username")
    password = data.get("pass") or data.get("password")

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
