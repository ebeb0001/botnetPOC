import os
import threading
from collections import defaultdict
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from common.config import env_bool, env_int
from common.http import post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "detector")
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
MITIGATOR_URL = os.getenv("MITIGATOR_URL", "").rstrip("/")
ALERT_FAILURE_THRESHOLD = env_int("ALERT_FAILURE_THRESHOLD", 3)
FORWARD_ALERTS = env_bool("FORWARD_ALERTS", True)

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
state_lock = threading.Lock()
events: list[dict[str, Any]] = []
alerts: list[dict[str, Any]] = []
failure_counts: dict[tuple[str, str], int] = defaultdict(int)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def token_valid() -> bool:
    supplied = request.headers.get("X-Simulation-Token", "")
    if not SIMULATION_TOKEN:
        return True
    return supplied == SIMULATION_TOKEN


def forward_alert(alert: dict[str, Any]) -> None:
    if not FORWARD_ALERTS or not MITIGATOR_URL:
        return
    try:
        post_json(f"{MITIGATOR_URL}/alerts", alert, token=SIMULATION_TOKEN)
    except Exception as exc:
        log_event(logger, "detector.alert_forward_failed", alert_id=alert.get("alert_id"), reason=str(exc))


def create_alert(alert_type: str, severity: str, source_event: dict[str, Any], **fields: Any) -> dict[str, Any]:
    alert = {
        "alert_id": f"alert-{len(alerts) + 1:04d}",
        "alert_type": alert_type,
        "severity": severity,
        "created_at": now_iso(),
        "source_event_type": source_event.get("event_type"),
        "device_id": source_event.get("device_id"),
        "scanner_id": source_event.get("scanner_id"),
        "target_url": source_event.get("target_url"),
        **fields,
    }
    alerts.append(alert)
    log_event(logger, "detector.alert", **alert)
    forward_alert(alert)
    return alert


def evaluate_event(event: dict[str, Any]) -> list[dict[str, Any]]:
    """Evaluate an incoming event and generate alerts if necessary."""
    event_type = event.get("event_type")
    new_alerts: list[dict[str, Any]] = []

    if event_type in {"auth.failure", "auth.lockout_triggered"}:
        key = (
            str(event.get("scanner_id", "unknown")), 
            str(event.get("device_id") or event.get("target_url") or "unknown")
        )
        failure_counts[key] += 1
        if failure_counts[key] == ALERT_FAILURE_THRESHOLD or event_type == "auth.lockout_triggered":
            new_alerts.append(create_alert("weak-credential-scan", "medium", event, failure_count=failure_counts[key]))

    if event_type == "scanner.weak_credential_found":
        new_alerts.append(create_alert("weak-credential-compromise", "high", event))
    elif event_type == "scanner.compromise_failed":
        new_alerts.append(
            create_alert(
                "compromise-failed",
                "info",
                event,
                reason=event.get("reason"),
                credential_attempts=event.get("credential_attempts"),
            )
        )
    elif event_type == "infection.simulated":
        new_alerts.append(create_alert("simulated-infection", "high", event))
    elif event_type == "c2.registration":
        new_alerts.append(create_alert("c2-registration", "high", event))
    elif event_type == "c2.commands_distributed":
        new_alerts.append(create_alert("command-distribution", "medium", event, command_count=event.get("command_count")))
    elif event_type == "target.hit_received":
        new_alerts.append(
            create_alert(
                "demo-target-hit",
                "info",
                event,
                command_id=event.get("command_id"),
                hit_id=event.get("hit_id"),
                total_hits=event.get("total_hits"),
            )
        )
    elif event_type == "command.single_request_executed":
        new_alerts.append(
            create_alert(
                "single-request-demo-impact",
                "medium",
                event,
                command_id=event.get("command_id"),
                demo_target_url=event.get("demo_target_url"),
                target_hit_count=event.get("target_hit_count"),
            )
        )
    elif event_type == "command.single_request_failed":
        new_alerts.append(create_alert("single-request-demo-failed", "low", event, command_id=event.get("command_id"), reason=event.get("reason")))
    elif event_type == "infection.blocked":
        new_alerts.append(create_alert("infection-blocked", "low", event))
    elif event_type == "mitigation.applied":
        new_alerts.append(create_alert("mitigation-applied", "info", event))

    return new_alerts


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME})


@app.post("/events")
def ingest_event() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/events")
        return jsonify({"error": "invalid simulation token"}), 403
    body = request.get_json(force=True, silent=True) or {}
    event = {"received_at": now_iso(), **body}
    with state_lock:
        events.append(event)
        generated_alerts = evaluate_event(event)
    log_event(logger, "detector.event_ingested", event_type=event.get("event_type"), source_service=event.get("source_service"), alert_count=len(generated_alerts))
    return jsonify({"accepted": True, "alerts": generated_alerts})


@app.get("/events")
def list_events() -> Any:
    with state_lock:
        return jsonify({"events": events, "count": len(events)})


@app.get("/alerts")
def list_alerts() -> Any:
    with state_lock:
        return jsonify({"alerts": alerts, "count": len(alerts)})


if __name__ == "__main__":
    log_event(
        logger, 
        "service.started", 
        port=5000, 
        alert_failure_threshold=ALERT_FAILURE_THRESHOLD, 
        forward_alerts=FORWARD_ALERTS
    )
    app.run(host="0.0.0.0", port=5000, threaded=True)
