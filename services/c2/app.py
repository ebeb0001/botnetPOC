import os
import threading
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from common.config import csv_list, safe_internal_service_url
from common.http import post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "c2-server")
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
DETECTOR_URL = os.getenv("DETECTOR_URL", "").rstrip("/")
ALLOWED_COMMANDS = set(csv_list(os.getenv("ALLOWED_COMMANDS", 
"collect_status,inventory,quarantine,rotate_credentials,single_request")))
REJECTED_COMMANDS = {"ddos", "attack", "flood", "syn_flood", "udp_flood", "scan_internet", "exploit"}
DEMO_TARGET_ALLOWED_HOSTS = os.getenv("ALLOWED_DEMO_TARGET_HOSTS", "target_server")
DEMO_TARGET_ALLOWED_PATHS = ("", "/", "/hit")
DEMO_TARGET_URL = safe_internal_service_url(
    os.getenv("DEMO_TARGET_URL", "http://target_server:8000/"),
    DEMO_TARGET_ALLOWED_HOSTS,
    allowed_paths=DEMO_TARGET_ALLOWED_PATHS,
)

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
state_lock = threading.Lock()
bots: dict[str, dict[str, Any]] = {}
commands: list[dict[str, Any]] = []
delivered: dict[str, set[str]] = {}


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


def normalize_single_request_target(raw_target: Any) -> str:
    target = str(raw_target or DEMO_TARGET_URL).strip() or DEMO_TARGET_URL
    return safe_internal_service_url(target, DEMO_TARGET_ALLOWED_HOSTS, allowed_paths=DEMO_TARGET_ALLOWED_PATHS)


def dispatch_command_to_registered_bots(command_record: dict[str, Any]) -> list[dict[str, Any]]:
    """Dispatch a command to all registered bots that match the target_device_id."""
    target_device_id = command_record.get("target_device_id")
    with state_lock:
        recipients = [
            (device_id, dict(bot))
            for device_id, bot in bots.items()
            if not bot.get("quarantined") and (target_device_id is None or target_device_id == device_id)
        ]

    dispatch_results: list[dict[str, Any]] = []
    for device_id, bot in recipients:
        device_url = str(bot.get("device_url", "")).rstrip("/")
        result: dict[str, Any] = {"device_id": device_id, "device_url": device_url, "delivered": False}
        try:
            response = post_json(f"{device_url}/command", command_record, token=SIMULATION_TOKEN)
            result["status_code"] = response.status_code
            try:
                result["body"] = response.json()
            except Exception:
                result["body"] = response.text
            result["delivered"] = response.ok
        except Exception as exc:
            result["error"] = str(exc)

        with state_lock:
            delivered.setdefault(device_id, set()).add(command_record["command_id"])
            if result.get("delivered") and device_id in bots:
                bots[device_id]["last_seen"] = now_iso()
        dispatch_results.append(result)
        log_event(
            logger,
            "c2.command_direct_dispatch",
            command_id=command_record["command_id"],
            command=command_record["command"],
            device_id=device_id,
            delivered=result["delivered"],
            status_code=result.get("status_code"),
        )

    if recipients: # Only log the aggregate distribution event if there were any recipients, to reduce noise in the logs
        log_event(
            logger,
            "c2.commands_distributed",
            command_id=command_record["command_id"],
            command=command_record["command"],
            count=len(recipients),
        )
        emit_detector_event(
            "c2.commands_distributed",
            command_id=command_record["command_id"],
            command=command_record["command"],
            command_count=len(recipients),
            device_id=str(target_device_id or ""),
        )
    return dispatch_results


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME})


@app.post("/bots/register")
def register_bot() -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/bots/register")
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    device_id = str(body.get("device_id", "")).strip()
    device_url = str(body.get("device_url", "")).strip()
    scanner_id = str(body.get("scanner_id", "")).strip()
    if not device_id or not device_url:
        return jsonify({"error": "device_id and device_url are required"}), 400

    with state_lock:
        existing = bots.get(device_id, {})
        bots[device_id] = {
            "device_id": device_id,
            "device_url": device_url,
            "scanner_id": scanner_id,
            "registered_at": existing.get("registered_at", now_iso()),
            "last_seen": now_iso(),
            "quarantined": existing.get("quarantined", False),
            "simulated": True,
        }

    log_event(logger, "c2.registration", device_id=device_id, device_url=device_url, scanner_id=scanner_id)
    emit_detector_event("c2.registration", device_id=device_id, target_url=device_url, scanner_id=scanner_id)
    return jsonify({"registered": True, "bot": bots[device_id]})


@app.get("/bots")
def list_bots() -> Any:
    with state_lock:
        return jsonify({"bots": list(bots.values()), "count": len(bots)})


@app.post("/bots/<device_id>/quarantine")
def quarantine_bot(device_id: str) -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/bots/quarantine", device_id=device_id)
        return jsonify({"error": "invalid simulation token"}), 403

    with state_lock:
        bot = bots.get(device_id)
        if not bot:
            return jsonify({"error": "unknown device_id"}), 404
        bot["quarantined"] = True
        bot["quarantined_at"] = now_iso()

    log_event(logger, "c2.bot_quarantined", device_id=device_id)
    emit_detector_event("c2.bot_quarantined", device_id=device_id, target_url=bot.get("device_url"))
    return jsonify({"quarantined": True, "device_id": device_id})


def create_command(require_token: bool) -> Any:
    if require_token and not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/commands")
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    command = str(body.get("command") or body.get("type") or "").strip()
    target_device_id = str(body.get("target_device_id", "")).strip() or None
    if not command:
        return jsonify({"accepted": False, "error": "command is required"}), 400
    if command in REJECTED_COMMANDS or command not in ALLOWED_COMMANDS:
        log_event(logger, "c2.command_rejected", command=command, reason="not allowed in safe lab")
        return jsonify({"accepted": False, "error": "command is not allowed in this safe simulation"}), 400

    target_url = None
    if command == "single_request":
        try:
            target_url = normalize_single_request_target(body.get("target") or body.get("target_url"))
        except ValueError as exc:
            log_event(logger, "c2.command_rejected", command=command, reason=str(exc))
            return jsonify({"accepted": False, "error": str(exc)}), 400

    command_id = f"cmd-{len(commands) + 1:04d}"
    command_record = {
        "command_id": command_id,
        "command": command,
        "target_device_id": target_device_id,
        "created_at": now_iso(),
        "simulated": True,
    }
    if target_url:
        command_record["target_url"] = target_url
    with state_lock:
        commands.append(command_record)

    log_event(logger, "c2.command_accepted", command_id=command_id, command=command, target_device_id=target_device_id)
    emit_detector_event("c2.command_accepted", command_id=command_id, command=command, device_id=target_device_id)
    dispatch_results = dispatch_command_to_registered_bots(command_record)
    return jsonify({"accepted": True, "command": command_record, "dispatch": {"count": len(dispatch_results), "results": dispatch_results}})


@app.post("/command")
def create_demo_command() -> Any:
    return create_command(require_token=False)


@app.post("/commands")
def create_token_command() -> Any:
    return create_command(require_token=True)


@app.get("/commands/<device_id>")
def commands_for_bot(device_id: str) -> Any:
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/commands/<device_id>", device_id=device_id)
        return jsonify({"error": "invalid simulation token"}), 403

    with state_lock:
        bot = bots.get(device_id)
        if not bot:
            return jsonify({"commands": [], "reason": "not registered"})
        if bot.get("quarantined"):
            log_event(logger, "c2.command_blocked_by_quarantine", device_id=device_id)
            return jsonify({"commands": [], "reason": "bot quarantined"})

        already = delivered.setdefault(device_id, set())
        pending = [
            command
            for command in commands
            if command["command_id"] not in already
            and (command["target_device_id"] is None or command["target_device_id"] == device_id)
        ]
        for command in pending:
            already.add(command["command_id"])
        bot["last_seen"] = now_iso()

    if pending:
        log_event(logger, "c2.commands_distributed", device_id=device_id, count=len(pending))
        emit_detector_event("c2.commands_distributed", device_id=device_id, command_count=len(pending))
    return jsonify({"commands": pending})


if __name__ == "__main__":
    log_event(logger, "service.started", port=5000, allowed_commands=sorted(ALLOWED_COMMANDS))
    app.run(host="0.0.0.0", port=5000, threaded=True)
