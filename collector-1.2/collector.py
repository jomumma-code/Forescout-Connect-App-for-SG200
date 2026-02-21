# collector.py
import importlib
import importlib.util
import sys
import json
import logging
import os
import hmac
import hashlib
import re
import threading
import time
from typing import Dict, Optional, Tuple, Any, List

from flask import Flask, request, jsonify

app = Flask(__name__)

# --------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------
logging.basicConfig(
    level=os.environ.get("COLLECTOR_LOG_LEVEL", "INFO").upper(),
    format="%(asctime)s [%(levelname)s] %(message)s",
)
logger = logging.getLogger("collector")
logging.getLogger("werkzeug").setLevel(logging.INFO)

# --------------------------------------------------------------------
# File-based security config (preferred), with env-var fallback
# --------------------------------------------------------------------
_SECURITY_PATHS = [
    os.path.join(os.path.dirname(__file__), "collector_security.json"),
    "/etc/sg200/collector_security.json",
]


def _load_security_config() -> Dict[str, Any]:
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
        v = _SEC_CFG.get("token")
        return str(v or "")
    return os.environ.get("SG200_COLLECTOR_TOKEN", "")


_ALLOWED_IPS = [ip.strip() for ip in _get_allowed_ips_raw().split(",") if ip.strip()]
_SHARED_TOKEN = _get_token_raw().strip()

# --------------------------------------------------------------------
# Cache (very small, per switch_ip, per endpoint)
# --------------------------------------------------------------------
_CACHE_TTL_S = int(os.environ.get("SG200_COLLECTOR_CACHE_TTL_S", "10"))
_CACHE_MAX_ENTRIES = int(os.environ.get("SG200_COLLECTOR_CACHE_MAX_ENTRIES", "64"))
_cache_lock = threading.Lock()
_cache: Dict[str, Tuple[float, Dict[str, Any]]] = {}

# Per-switch lock to avoid concurrent polling the same switch
_switch_locks_lock = threading.Lock()
_switch_locks: Dict[str, threading.Lock] = {}


def _get_switch_lock(ip: str) -> threading.Lock:
    with _switch_locks_lock:
        if ip not in _switch_locks:
            _switch_locks[ip] = threading.Lock()
        return _switch_locks[ip]


def _cache_get(key: str) -> Optional[Tuple[float, Dict[str, Any]]]:
    with _cache_lock:
        item = _cache.get(key)
        if not item:
            return None
        ts, payload = item
        if (time.time() - ts) > _CACHE_TTL_S:
            _cache.pop(key, None)
            return None
        return ts, payload


def _cache_put(key: str, payload: Dict[str, Any]) -> None:
    with _cache_lock:
        if len(_cache) >= _CACHE_MAX_ENTRIES:
            # Drop oldest
            oldest_key = None
            oldest_ts = None
            for k, (ts, _) in _cache.items():
                if oldest_ts is None or ts < oldest_ts:
                    oldest_ts = ts
                    oldest_key = k
            if oldest_key is not None:
                _cache.pop(oldest_key, None)
        _cache[key] = (time.time(), payload)


# --------------------------------------------------------------------
# Auth helpers
# --------------------------------------------------------------------
def _client_ip() -> str:
    # If behind proxy, user should configure X-Forwarded-For properly; otherwise, this is direct.
    return request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip()


def _timing_safe_equals(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode("utf-8"), b.encode("utf-8"))


def _authorize_request() -> Tuple[bool, Tuple[Dict[str, Any], int]]:
    # IP allowlist (optional)
    if _ALLOWED_IPS:
        ip = _client_ip()
        if ip not in _ALLOWED_IPS:
            return False, ({"error": f"Forbidden (IP not allowed): {ip}"}, 403)

    # Shared token (optional)
    if _SHARED_TOKEN:
        token = request.headers.get("X-Auth-Token", "").strip()
        if not token or not _timing_safe_equals(token, _SHARED_TOKEN):
            return False, ({"error": "Unauthorized (missing/invalid token)"}, 401)

    return True, ({}, 200)


# --------------------------------------------------------------------
# Dynamic scraper loading
# --------------------------------------------------------------------
def _load_scraper_module(module_basename: str) -> Any:
    """
    Load scraper module by basename.
    Searches:
      - ./scrapers/{module_basename}.py
      - ./{module_basename}.py
    """
    base_dir = os.path.dirname(os.path.abspath(__file__))
    candidates = [
        os.path.join(base_dir, "scrapers", f"{module_basename}.py"),
        os.path.join(base_dir, f"{module_basename}.py"),
    ]

    last_err = None
    for path in candidates:
        try:
            if os.path.exists(path):
                mod_name = f"scrapers.{module_basename}"
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec is None or spec.loader is None:
                    continue
                mod = importlib.util.module_from_spec(spec)
                sys.modules[mod_name] = mod
                spec.loader.exec_module(mod)  # type: ignore
                logger.info("Loaded scraper module %s from %s", mod_name, path)
                return mod
        except Exception as e:
            last_err = e
    raise RuntimeError(f"Failed loading scraper '{module_basename}'. Last error: {last_err}")


def _select_sg200_scraper_module(variant: str) -> str:
    """
    Choose scraper module by request JSON field `variant`.
    SG200-26 uses sg200_client_sg20026, Nikola uses sg200_client_nikola.
    """
    v = (variant or "").strip().lower()

    if v in ("nikola", "sg2008", "sg200-8"):
        return "sg200_client_nikola"

    if v in ("sg20026", "sg200-26", "sg200_26", "", None):
        return "sg200_client_sg20026"

    # allow future drop-ins (variant can be a module name)
    return v


def _poll_sg200(switch_ip: str, username: str, password: str, variant: str) -> Dict[str, Any]:
    module_name = _select_sg200_scraper_module(variant)
    sg = _load_scraper_module(module_name)

    # Scraper must implement fetch_poll_bundle(ip,user,pass)
    if not hasattr(sg, "fetch_poll_bundle"):
        raise RuntimeError(f"Scraper '{module_name}' does not define fetch_poll_bundle()")

    return sg.fetch_poll_bundle(switch_ip, username, password)


# --------------------------------------------------------------------
# Netgear endpoints (unchanged)
# --------------------------------------------------------------------
def _load_netgear_module() -> Any:
    return _load_scraper_module("netgear_client")


def _poll_netgear(router_ip: str, username: str, password: str) -> Dict[str, Any]:
    ng = _load_netgear_module()
    if not hasattr(ng, "fetch_devices"):
        raise RuntimeError("netgear_client missing fetch_devices()")
    return ng.fetch_devices(router_ip, username, password)


# --------------------------------------------------------------------
# MAC helpers
# --------------------------------------------------------------------
_MAC_HEX_RE = re.compile(r"^[0-9a-f]{12}$", re.IGNORECASE)


def _normalize_mac_for_count(mac: Optional[str]) -> Optional[str]:
    s = str(mac or "").strip().lower()
    if not s:
        return None
    s = s.replace(":", "").replace("-", "").replace(".", "")
    if not _MAC_HEX_RE.match(s):
        return None
    return s


def _get_entry_mac(entry: Dict[str, Any]) -> Optional[str]:
    for k in ("mac", "mac_address", "macAddress"):
        v = entry.get(k)
        if v:
            return str(v)
    return None


def _get_entry_port(entry: Dict[str, Any]) -> Optional[str]:
    for k in ("port_index", "portIndex", "port", "port_id", "portId", "interface", "Interface"):
        v = entry.get(k)
        if v is not None:
            s = str(v).strip()
            if s:
                return s
    return None


def _normalize_vlan(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(str(v).strip())
    except Exception:
        return None


def _normalize_mac_table_entries(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Normalize scraper MAC table entries into the sg200-26 schema:

      - mac: passthrough (no value rewriting)
      - port_index: taken from port_index/portIndex/port/... (no value rewriting)
      - vlan: int, derived from vlan/vlan_id/vlanId when present
      - port_type: preserved if provided by the scraper

    Any other fields are dropped to keep the output consistent across variants.
    """
    out: List[Dict[str, Any]] = []
    for e in entries or []:
        if not isinstance(e, dict):
            continue

        mac = _get_entry_mac(e)
        port = _get_entry_port(e)

        vlan_raw = e.get("vlan")
        if vlan_raw is None:
            vlan_raw = e.get("vlan_id")
        if vlan_raw is None:
            vlan_raw = e.get("vlanId")
        vlan = _normalize_vlan(vlan_raw)

        e2: Dict[str, Any] = {}
        if mac is not None:
            e2["mac"] = mac
        if port is not None:
            e2["port_index"] = port
        if vlan is not None:
            e2["vlan"] = vlan
        if e.get("port_type") is not None:
            e2["port_type"] = e.get("port_type")

        out.append(e2)
    return out


def _annotate_port_type(entries: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """
    Add port_type to each entry based on MAC fanout per port.

    Rules:
      - port_type='bridge' if a port has >1 unique MAC in the returned table
      - port_type='device' otherwise

    If an entry already contains port_type, it is preserved.
    """
    port_to_macs: Dict[str, set] = {}

    for e in entries:
        port = _get_entry_port(e)
        if not port:
            continue
        port_key = port.lower()
        mac = _get_entry_mac(e)
        mac_norm = _normalize_mac_for_count(mac)
        if not mac_norm:
            continue
        port_to_macs.setdefault(port_key, set()).add(mac_norm)

    port_counts = {p: len(macs) for p, macs in port_to_macs.items()}

    annotated: List[Dict[str, Any]] = []
    for e in entries:
        # Preserve scraper-provided port_type if present
        if isinstance(e, dict) and e.get("port_type") is not None:
            annotated.append(dict(e))
            continue

        port = _get_entry_port(e)
        port_key = port.lower() if port else ""
        port_type = "bridge" if port_counts.get(port_key, 0) > 1 else "device"
        e2 = dict(e)
        e2["port_type"] = port_type
        annotated.append(e2)

    return annotated


# --------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------
@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok"})


@app.route("/sg200/poll", methods=["POST"])
def sg200_poll():
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

    data = request.get_json(silent=True) or {}
    switch_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")
    variant = data.get("variant", "sg20026")

    if not switch_ip or not username or not password:
        return jsonify({"error": "ip, user, and pass fields are required in JSON body"}), 400

    switch_ip = str(switch_ip).strip()
    username = str(username)
    password = str(password)

    t0 = time.perf_counter()
    logger.info("Request for SG200 poll bundle from %s (variant=%s)", switch_ip, str(variant))

    cached = _cache_get(switch_ip)
    if cached is not None:
        ts, payload = cached
        age = time.time() - ts
        mac_n = len((payload.get("mac_table") or {}).get("entries") or [])
        logger.info("SG200 poll cache HIT for %s (age=%.1fs, mac_entries=%d)", switch_ip, age, mac_n)
        return jsonify(payload), 200

    lock = _get_switch_lock(switch_ip)
    with lock:
        cached = _cache_get(switch_ip)
        if cached is not None:
            ts, payload = cached
            age = time.time() - ts
            mac_n = len((payload.get("mac_table") or {}).get("entries") or [])
            logger.info("SG200 poll cache HIT-after-wait for %s (age=%.1fs, mac_entries=%d)", switch_ip, age, mac_n)
            return jsonify(payload), 200

        try:
            out = _poll_sg200(switch_ip, username, password, str(variant))

            errors = {}
            summary_error = out.pop("system_summary_error", None)
            if summary_error:
                errors["system_summary"] = summary_error

            try:
                sys_summary_obj = out.get("system_summary") or {}
                if isinstance(sys_summary_obj, dict):
                    sys_summary_obj.pop("switch_ip", None)
                    out["system_summary"] = sys_summary_obj
            except Exception:
                pass

            try:
                mac_table_obj = out.get("mac_table") or {}
                if isinstance(mac_table_obj, dict):
                    mac_table_obj.pop("switch_ip", None)
                    entries_tmp = mac_table_obj.get("entries") or []
                    if isinstance(entries_tmp, list):
                        for ent in entries_tmp:
                            if isinstance(ent, dict):
                                ent.pop("switch_ip", None)
                    mac_table_obj["entries"] = entries_tmp
                    out["mac_table"] = mac_table_obj
            except Exception:
                pass

            if errors:
                out["errors"] = errors

            mac_table = out.get("mac_table") or {}
            entries = mac_table.get("entries") or []
            if not isinstance(entries, list):
                entries = []

            # Normalize schema across variants (Nikola -> sg200-26 keys/types)
            entries = _normalize_mac_table_entries(entries)

            logger.info("SG200 MAC table returned %d entries before port_type annotation", len(entries))
            entries_annotated = _annotate_port_type(entries)
            logger.info("SG200 MAC table returned %d entries after port_type annotation", len(entries_annotated))

            mac_table["entries"] = entries_annotated
            out["mac_table"] = mac_table

            sys_sum = out.get("system_summary") or {}
            if isinstance(sys_sum, dict):
                fields = [k for k in ("host_name", "serial_number", "model_description", "firmware_version") if k in sys_sum]
                logger.info("SG200 system summary collected (%s)", ",".join(fields) if fields else "ok")
            else:
                logger.info("SG200 system summary collected (non-dict)")

            _cache_put(switch_ip, out)

            dt = time.perf_counter() - t0
            logger.info("SG200 poll bundle COMPLETE for %s (%.2fs)", switch_ip, dt)
            return jsonify(out), 200

        except Exception as e:
            dt = time.perf_counter() - t0
            logger.exception("Error fetching SG200 poll bundle from %s after %.2fs", switch_ip, dt)
            return jsonify({"error": str(e)}), 500


@app.route("/netgear/devices", methods=["POST"])
def netgear_devices():
    authorized, error = _authorize_request()
    if not authorized:
        return jsonify(error[0]), error[1]

    data = request.get_json(silent=True) or {}
    router_ip = data.get("ip")
    username = data.get("user")
    password = data.get("pass")

    if not router_ip or not username or not password:
        return jsonify({"error": "ip, user, and pass fields are required in JSON body"}), 400

    router_ip = str(router_ip).strip()
    username = str(username)
    password = str(password)

    try:
        out = _poll_netgear(router_ip, username, password)
        return jsonify(out), 200
    except Exception as e:
        logger.exception("Error fetching Netgear devices from %s", router_ip)
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    host = os.environ.get("SG200_COLLECTOR_HOST", "0.0.0.0")
    port = int(os.environ.get("SG200_COLLECTOR_PORT", "8081"))
    app.run(host=host, port=port)