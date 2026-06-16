import os
import threading
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from common.config import env_int
from common.http import post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "demo-target")
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
DETECTOR_URL = os.getenv("DETECTOR_URL", "").rstrip("/")
PORT = env_int("PORT", 8000)

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
state_lock = threading.Lock()
hits: list[dict[str, Any]] = []


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def token_valid() -> bool:
    supplied = request.headers.get("X-Simulation-Token", "")
    if not SIMULATION_TOKEN:
        return True
    return supplied == SIMULATION_TOKEN


def emit_detector_event(event_type: str, **fields: Any) -> None:
    if not DETECTOR_URL:
        return
    payload = {"event_type": event_type, "source_service": SERVICE_NAME, **fields}
    try:
        post_json(f"{DETECTOR_URL}/events", payload, token=SIMULATION_TOKEN)
    except Exception as exc:
        log_event(logger, "detector.emit_failed", reason=str(exc), event_type=event_type)


def record_hit(body: dict[str, Any], scenario: str) -> dict[str, Any]:
    with state_lock:
        hit = {
            "hit_id": f"hit-{len(hits) + 1:04d}",
            "received_at": now_iso(),
            "source_device_id": str(body.get("device_id", "")),
            "source_device_profile": str(body.get("device_profile", "")),
            "command_id": str(body.get("command_id", "")),
            "scenario": scenario,
            "remote_addr": request.remote_addr,
        }
        hits.append(hit)
        count = len(hits)

    log_event(logger, "target.hit_received", **hit, total_hits=count)
    emit_detector_event(
        "target.hit_received",
        device_id=hit["source_device_id"],
        command_id=hit["command_id"],
        hit_id=hit["hit_id"],
        total_hits=count,
    )
    return {"accepted": True, "hit": hit, "count": count}


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME})


@app.route("/", methods=["GET", "POST"])
def receive_root_hit() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/")
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    return jsonify(record_hit(body, "single_request_demo"))


@app.post("/hit")
def receive_hit() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/hit")
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    return jsonify(record_hit(body, "single_request_demo"))


@app.get("/hits")
def hit_count() -> Any:
    with state_lock:
        count = len(hits)
    return jsonify({"hits": count, "count": count})


@app.get("/hit-log")
def list_hits() -> Any:
    with state_lock:
        return jsonify({"hits": hits, "count": len(hits)})


@app.post("/reset")
def reset_hits() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/reset")
        return jsonify({"error": "invalid simulation token"}), 403
    with state_lock:
        previous_count = len(hits)
        hits.clear()
    log_event(logger, "target.reset", previous_count=previous_count)
    return jsonify({"reset": True, "previous_count": previous_count})


if __name__ == "__main__":
    log_event(logger, "service.started", port=PORT)
    app.run(host="0.0.0.0", port=PORT, threaded=True)
