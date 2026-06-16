from __future__ import annotations

import os
import threading
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from common.config import csv_list, env_bool
from common.http import post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "mitigator")
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
C2_URL = os.getenv("C2_URL", "http://c2:5000").rstrip("/")
DEVICE_URLS = csv_list(os.getenv("DEVICE_URLS", ""))
AUTO_MITIGATE = env_bool("AUTO_MITIGATE", False)
AUTO_MITIGATE_ALERT_TYPES = set(
    csv_list(os.getenv("AUTO_MITIGATE_ALERT_TYPES", "weak-credential-compromise,simulated-infection,c2-registration"))
)

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
state_lock = threading.Lock()
actions: list[dict[str, Any]] = []


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def token_valid() -> bool:
    supplied = request.headers.get("X-Simulation-Token", "")
    if not SIMULATION_TOKEN:
        return True
    return supplied == SIMULATION_TOKEN


def record_action(action_type: str, **fields: Any) -> dict[str, Any]:
    action = {"action_id": f"action-{len(actions) + 1:04d}", "action_type": action_type, "created_at": now_iso(), **fields}
    actions.append(action)
    log_event(logger, "mitigator.action", **action)
    return action


def mitigate_device_url(device_url: str) -> dict[str, Any]:
    response = post_json(f"{device_url.rstrip('/')}/mitigate", {"source": SERVICE_NAME}, token=SIMULATION_TOKEN)
    return {"target_url": device_url, "status_code": response.status_code, "body": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text}


def quarantine_c2_device(device_id: str) -> dict[str, Any]:
    response = post_json(f"{C2_URL}/bots/{device_id}/quarantine", {"source": SERVICE_NAME}, token=SIMULATION_TOKEN)
    body: Any
    try:
        body = response.json()
    except Exception:
        body = response.text
    return {"device_id": device_id, "status_code": response.status_code, "body": body}


def apply_mitigation(alert: dict[str, Any]) -> dict[str, Any]:
    device_id = str(alert.get("device_id") or "")
    target_url = str(alert.get("target_url") or "")
    results: dict[str, Any] = {"alert_id": alert.get("alert_id"), "device_results": [], "c2_result": None}

    if target_url:
        try:
            results["device_results"].append(mitigate_device_url(target_url))
        except Exception as exc:
            results["device_results"].append({"target_url": target_url, "error": str(exc)})

    if device_id:
        try:
            results["c2_result"] = quarantine_c2_device(device_id)
        except Exception as exc:
            results["c2_result"] = {"device_id": device_id, "error": str(exc)}

    with state_lock:
        record_action("alert-mitigation", alert_type=alert.get("alert_type"), results=results)
    return results


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME})


@app.post("/alerts")
def receive_alert() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/alerts")
        return jsonify({"error": "invalid simulation token"}), 403
    alert = request.get_json(force=True, silent=True) or {}
    alert_type = str(alert.get("alert_type") or "")
    log_event(logger, "mitigator.alert_received", alert_id=alert.get("alert_id"), alert_type=alert_type, auto_mitigate=AUTO_MITIGATE)
    if not AUTO_MITIGATE or alert_type not in AUTO_MITIGATE_ALERT_TYPES:
        with state_lock:
            record_action("alert-observed", alert_id=alert.get("alert_id"), alert_type=alert_type)
        reason = "AUTO_MITIGATE is false" if not AUTO_MITIGATE else "alert type is not auto-mitigated"
        return jsonify({"accepted": True, "mitigated": False, "reason": reason})
    results = apply_mitigation(alert)
    return jsonify({"accepted": True, "mitigated": True, "results": results})


@app.post("/mitigate/all")
def mitigate_all() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/mitigate/all")
        return jsonify({"error": "invalid simulation token"}), 403

    results = []
    for device_url in DEVICE_URLS:
        try:
            results.append(mitigate_device_url(device_url))
        except Exception as exc:
            results.append({"target_url": device_url, "error": str(exc)})

    with state_lock:
        record_action("manual-mitigate-all", results=results)
    return jsonify({"mitigated": True, "results": results})


@app.post("/quarantine/<device_id>")
def quarantine(device_id: str) -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/quarantine/<device_id>", device_id=device_id)
        return jsonify({"error": "invalid simulation token"}), 403
    result = quarantine_c2_device(device_id)
    with state_lock:
        record_action("manual-quarantine", device_id=device_id, result=result)
    return jsonify(result)


@app.get("/actions")
def list_actions() -> Any:
    with state_lock:
        return jsonify({"actions": actions, "count": len(actions)})


if __name__ == "__main__":
    log_event(
        logger,
        "service.started",
        port=5000,
        auto_mitigate=AUTO_MITIGATE,
        auto_mitigate_alert_types=sorted(AUTO_MITIGATE_ALERT_TYPES),
        device_urls=DEVICE_URLS,
    )
    app.run(host="0.0.0.0", port=5000, threaded=True)
