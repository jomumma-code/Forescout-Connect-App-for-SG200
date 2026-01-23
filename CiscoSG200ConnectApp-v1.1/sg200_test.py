#!/usr/bin/env python3
"""
Cisco SG200 Connect App - Test script (multi-switch).

Validates:
  - Collector is reachable (/health)
  - For each configured switch (1..16):
      - MAC table fetch works (/sg200/mac-table) [required]
      - System summary fetch works (/sg200/system-summary) [best-effort]

Progress visibility:
  - The Connect UI only displays results after the script finishes.
  - This script logs per-switch progress to the Connect python logs in real time.

Timeouts:
  - Collector calls use 45 seconds (same as production polling).
"""

import logging
import time
import requests

logger = logging.getLogger(__name__)

response = {"succeeded": False}

TIMEOUT_SECONDS = 45


def _get_param(key, default=None):
    val = params.get(key, default)  # noqa: F821
    if isinstance(val, str):
        return val.strip()
    return val


def _headers():
    h = {"Content-Type": "application/json"}
    token = _get_param("connect_ciscosg200_collector_token", "")
    if token:
        h["X-Collector-Token"] = token
    return h


def _collector_base():
    host = _get_param("connect_ciscosg200_collector_host", "")
    port = str(_get_param("connect_ciscosg200_collector_port", "8081") or "8081")
    if not host:
        return ""
    return "http://{0}:{1}".format(host, port)


def _switch_candidates():
    candidates = []
    partial_slots = []

    # Slot 1 (legacy IDs; required in UI)
    ip1 = _get_param("connect_ciscosg200_switch_ip", "")
    user1 = _get_param("connect_ciscosg200_switch_username", "")
    pw1 = _get_param("connect_ciscosg200_switch_password", "")
    if ip1 or user1 or pw1:
        if ip1 and user1 and pw1:
            candidates.append({"idx": 1, "ip": ip1, "user": user1, "pass": pw1})
        else:
            partial_slots.append(1)

    # Slots 2..16
    for i in range(2, 17):
        ip_i = _get_param("connect_ciscosg200_switch{0}_ip".format(i), "")
        user_i = _get_param("connect_ciscosg200_switch{0}_username".format(i), "")
        pw_i = _get_param("connect_ciscosg200_switch{0}_password".format(i), "")
        if ip_i or user_i or pw_i:
            if ip_i and user_i and pw_i:
                candidates.append({"idx": i, "ip": ip_i, "user": user_i, "pass": pw_i})
            else:
                partial_slots.append(i)

    return candidates, partial_slots


def _err_text(resp_obj):
    # Keep UI summary concise. Prefer collector-provided JSON error.
    try:
        data = resp_obj.json()
        if isinstance(data, dict):
            e = data.get("error") or data.get("detail") or ""
            if e:
                return str(e).replace("\n", " ").replace("\r", " ")[:220]
    except Exception:
        pass
    txt = (resp_obj.text or "").replace("\n", " ").replace("\r", " ")
    return txt[:220]


try:
    base = _collector_base()
    if not base:
        response["succeeded"] = False
        response["result_msg"] = "Missing required setting: connect_ciscosg200_collector_host"
    else:
        # Health check first (fast fail if collector unreachable)
        logger.info("TEST: collector health check start")
        r0 = requests.get(base + "/health", timeout=TIMEOUT_SECONDS)
        logger.info("TEST: collector /health HTTP %s", r0.status_code)
        if r0.status_code != 200:
            raise RuntimeError("Collector /health returned HTTP {0}".format(r0.status_code))

        candidates, partial_slots = _switch_candidates()
        if partial_slots:
            response["succeeded"] = False
            response["result_msg"] = "Incomplete switch credentials for slot(s): {0}".format(
                ", ".join([str(x) for x in partial_slots])
            )
        elif not candidates:
            response["succeeded"] = False
            response["result_msg"] = "No switches configured. Provide Switch 1 IP/Login/Password."
        else:
            ok_msgs = []
            fail_msgs = []

            for sw in candidates:
                idx = sw["idx"]
                sw_label = "SWITCH_{0}".format(idx)
                sw_ip = sw["ip"]

                logger.info("TEST: %s %s - start", sw_label, sw_ip)

                payload = {"ip": sw_ip, "user": sw["user"], "pass": sw["pass"]}

                # MAC table (required)
                mac_status = None
                mac_dt = 0.0
                mac_entries = None
                mac_err = ""

                t1 = time.time()
                try:
                    logger.info("TEST: %s %s - requesting mac-table", sw_label, sw_ip)
                    r1 = requests.post(
                        base + "/sg200/mac-table",
                        json=payload,
                        headers=_headers(),
                        timeout=TIMEOUT_SECONDS,
                    )
                    mac_dt = time.time() - t1
                    mac_status = r1.status_code
                    logger.info("TEST: %s %s - mac-table HTTP %s in %.2fs", sw_label, sw_ip, mac_status, mac_dt)

                    if mac_status == 200:
                        data = r1.json() if r1.text else {}
                        entries = data.get("entries") or []
                        mac_entries = len(entries) if isinstance(entries, list) else 0
                    else:
                        mac_err = _err_text(r1)

                except Exception as exc:
                    mac_dt = time.time() - t1
                    mac_status = "EXC"
                    mac_err = str(exc)[:220]
                    logger.warning("TEST: %s %s - mac-table exception: %s", sw_label, sw_ip, exc)

                # System summary (best-effort; run even if mac-table failed)
                sum_status = None
                sum_dt = 0.0
                hn = ""
                sn = ""
                fw = ""
                md = ""
                sum_err = ""

                t2 = time.time()
                try:
                    logger.info("TEST: %s %s - requesting system-summary", sw_label, sw_ip)
                    r2 = requests.post(
                        base + "/sg200/system-summary",
                        json=payload,
                        headers=_headers(),
                        timeout=TIMEOUT_SECONDS,
                    )
                    sum_dt = time.time() - t2
                    sum_status = r2.status_code
                    logger.info("TEST: %s %s - system-summary HTTP %s in %.2fs", sw_label, sw_ip, sum_status, sum_dt)

                    if sum_status == 200 and r2.text:
                        ss = r2.json()
                        hn = (ss.get("host_name") or "").strip()
                        sn = (ss.get("serial_number") or "").strip()
                        fw = (ss.get("firmware_version") or "").strip()
                        md = (ss.get("model_description") or "").strip()
                    elif sum_status != 200:
                        sum_err = _err_text(r2)

                except Exception as exc:
                    sum_dt = time.time() - t2
                    sum_status = "EXC"
                    sum_err = str(exc)[:220]
                    logger.info("TEST: %s %s - system-summary exception (best-effort): %s", sw_label, sw_ip, exc)

                logger.info("TEST: %s %s - done", sw_label, sw_ip)

                # Compose concise per-switch UI summary
                mac_part = "mac={0}({1:.1f}s)".format(mac_status, mac_dt)
                if mac_status == 200 and mac_entries is not None:
                    mac_part += " entries={0}".format(mac_entries)
                elif mac_err:
                    mac_part += " err={0}".format(mac_err)

                sum_part = "summary={0}({1:.1f}s)".format(sum_status, sum_dt)
                extra = []
                if hn:
                    extra.append("host_name={0}".format(hn))
                if sn:
                    extra.append("serial_number={0}".format(sn))
                if fw:
                    extra.append("firmware_version={0}".format(fw))
                if md:
                    extra.append("model_description={0}".format(md))
                if extra:
                    sum_part += " " + ", ".join(extra)
                elif sum_err:
                    sum_part += " err={0}".format(sum_err)

                sw_msg = "{0} {1}: {2}; {3}".format(sw_label, sw_ip, mac_part, sum_part)

                if mac_status == 200:
                    ok_msgs.append(sw_msg)
                else:
                    fail_msgs.append(sw_msg)

            # Final verdict: fail if ANY configured switch failed mac-table
            if fail_msgs:
                response["succeeded"] = False
                msg = "Collector reachable. Some switches failed. "
                if ok_msgs:
                    msg += "OK: " + " | ".join(ok_msgs) + ". "
                msg += "FAIL: " + " | ".join(fail_msgs)
                msg += " (See Connect python logs for step-by-step progress.)"
                response["result_msg"] = msg
            else:
                response["succeeded"] = True
                response["result_msg"] = "Collector reachable. All configured switches OK: " + " | ".join(ok_msgs)

except Exception as exc:
    response["succeeded"] = False
    response["result_msg"] = "Test execution failed."
    response["error"] = str(exc)
