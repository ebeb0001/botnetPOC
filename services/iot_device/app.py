import os
import threading
import time
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify, request

from common.config import Credential, env_bool, env_float, env_int, first_credential, \
    parse_credentials, safe_internal_service_url
from common.http import post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "iot-device")
DEVICE_ID = os.getenv("DEVICE_ID", SERVICE_NAME)
DEVICE_PROFILE = os.getenv("DEVICE_PROFILE", "generic-iot")
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
DETECTOR_URL = os.getenv("DETECTOR_URL", "").rstrip("/")
MITIGATION_ENABLED = env_bool("MITIGATION_ENABLED", False)
INFECTION_ALLOWED = env_bool("INFECTION_ALLOWED", not MITIGATION_ENABLED)
LOCKOUT_THRESHOLD = env_int("LOCKOUT_THRESHOLD", 5)
LOCKOUT_SECONDS = env_float("LOCKOUT_SECONDS", 20.0)
DEMO_TARGET_ALLOWED_HOSTS = os.getenv("ALLOWED_DEMO_TARGET_HOSTS", "target_server")
DEMO_TARGET_ALLOWED_PATHS = ("", "/", "/hit")
DEMO_TARGET_URL = safe_internal_service_url(
    os.getenv("DEMO_TARGET_URL", "http://target_server:8000/"),
    DEMO_TARGET_ALLOWED_HOSTS,
    allowed_paths=DEMO_TARGET_ALLOWED_PATHS,
)
credentials = parse_credentials(os.getenv("DEVICE_CREDENTIALS", "admin:admin"))
primary_credential = first_credential(credentials) or Credential("admin", "admin")

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
state_lock = threading.Lock()
state: dict[str, Any] = {
    "infected": False,
    "infected_by": None,
    "infected_at": None,
    "failed_attempts": 0,
    "locked_until": 0.0,
    "mitigated_at": None,
    "last_command": None,
    "last_demo_request": None,
}


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
    payload = {
        "event_type": event_type,
        "source_service": SERVICE_NAME,
        "device_id": DEVICE_ID,
        "device_profile": DEVICE_PROFILE,
        "target_url": request.host_url.rstrip("/"),
        **fields,
    }
    try:
        post_json(f"{DETECTOR_URL}/events", payload, token=SIMULATION_TOKEN)
    except Exception as exc:
        log_event(logger, "detector.emit_failed", reason=str(exc), event_type=event_type)


def credential_matches(username: str, password: str) -> bool:
    return any(credential.username == username and credential.password == password for credential in credentials)


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME, "device_id": DEVICE_ID})


@app.get("/status")
def status() -> Any:
    with state_lock:
        locked_for = max(0.0, state["locked_until"] - time.time())
        return jsonify(
            {
                "device_id": DEVICE_ID,
                "device_profile": DEVICE_PROFILE,
                "infected": state["infected"],
                "infected_by": state["infected_by"],
                "mitigation_enabled": MITIGATION_ENABLED,
                "infection_allowed": INFECTION_ALLOWED,
                "failed_attempts": state["failed_attempts"],
                "locked_for_seconds": round(locked_for, 1),
                "last_command": state["last_command"],
                "last_demo_request": state["last_demo_request"],
            }
        )


@app.post("/login")
def login() -> Any:
    body = request.get_json(force=True, silent=True) or {}
    username = str(body.get("username", ""))
    password = str(body.get("password", ""))
    scanner_id = str(body.get("scanner_id", "unknown-scanner"))

    with state_lock:
        if state["locked_until"] > time.time():
            locked_for = round(state["locked_until"] - time.time(), 1)
            log_event(logger, "auth.locked", device_id=DEVICE_ID, scanner_id=scanner_id, locked_for_seconds=locked_for)
            emit_detector_event("auth.locked", scanner_id=scanner_id, username=username, locked_for_seconds=locked_for)
            return jsonify({"authenticated": False, "error": "device locked"}), 423

        if credential_matches(username, password):
            state["failed_attempts"] = 0
            log_event(logger, "auth.success", device_id=DEVICE_ID, scanner_id=scanner_id, username=username)
            emit_detector_event("auth.success", scanner_id=scanner_id, username=username)
            return jsonify({"authenticated": True, "session_token": "simulated-session", "device_id": DEVICE_ID})

        state["failed_attempts"] += 1
        failed_attempts = state["failed_attempts"]
        if MITIGATION_ENABLED and failed_attempts >= LOCKOUT_THRESHOLD:
            state["locked_until"] = time.time() + LOCKOUT_SECONDS
            event_type = "auth.lockout_triggered"
        else:
            event_type = "auth.failure"

    log_event(
        logger, 
        event_type, 
        device_id=DEVICE_ID, 
        scanner_id=scanner_id, 
        username=username, 
        failed_attempts=failed_attempts
    )
    emit_detector_event(event_type, scanner_id=scanner_id, username=username, failed_attempts=failed_attempts)
    return jsonify({"authenticated": False, "error": "invalid credentials"}), 401


@app.post("/infect")
def infect() -> Any:
    """Simulate an infection event on the device."""
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/infect", device_id=DEVICE_ID)
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    scanner_id = str(body.get("scanner_id", "unknown-scanner"))
    credential = body.get("credential") if isinstance(body.get("credential"), dict) else {}

    with state_lock:
        if MITIGATION_ENABLED or not INFECTION_ALLOWED:
            log_event(
                logger, 
                "infection.blocked", 
                device_id=DEVICE_ID, 
                scanner_id=scanner_id, 
                reason="mitigation enabled"
            )
            emit_detector_event("infection.blocked", scanner_id=scanner_id, reason="mitigation enabled")
            return jsonify({"infected": False, "blocked": True, "device_id": DEVICE_ID})

        if state["infected"]:
            return jsonify({"infected": True, "already_infected": True, "device_id": DEVICE_ID})

        state["infected"] = True
        state["infected_by"] = scanner_id
        state["infected_at"] = now_iso()

    log_event(
        logger, 
        "infection.simulated", 
        device_id=DEVICE_ID, 
        scanner_id=scanner_id, 
        username=credential.get("username")
    )
    emit_detector_event("infection.simulated", scanner_id=scanner_id, username=credential.get("username"))
    return jsonify({"infected": True, "device_id": DEVICE_ID, "simulated": True})


@app.post("/command")
def command() -> Any:
    """Simulate receiving a command from the detector."""
    if not token_valid():
        log_event(logger, "auth.invalid_token", endpoint="/command", device_id=DEVICE_ID)
        return jsonify({"error": "invalid simulation token"}), 403

    body = request.get_json(force=True, silent=True) or {}
    command_name = str(body.get("command", ""))
    command_id = str(body.get("command_id", ""))

    with state_lock:
        if not state["infected"]:
            log_event(
                logger, 
                "command.rejected_not_infected", 
                device_id=DEVICE_ID, 
                command=command_name, 
                command_id=command_id
            )
            return jsonify({"executed": False, "reason": "device is not infected"})
        if command_name == "quarantine":
            state["infected"] = False
            state["mitigated_at"] = now_iso()
            state["last_command"] = command_name
            log_event(logger, "mitigation.command_quarantine", device_id=DEVICE_ID, command_id=command_id)
            emit_detector_event("mitigation.command_quarantine", command_id=command_id)
            return jsonify({"executed": True, "command": command_name, "mitigated": True})

        state["last_command"] = command_name

    if command_name == "single_request":
        try:
            target_url = safe_internal_service_url(
                str(body.get("target_url") or body.get("target") or DEMO_TARGET_URL),
                DEMO_TARGET_ALLOWED_HOSTS,
                allowed_paths=DEMO_TARGET_ALLOWED_PATHS,
            )
        except ValueError as exc:
            log_event(
                logger, 
                "command.single_request_rejected", 
                device_id=DEVICE_ID, 
                command_id=command_id, 
                reason=str(exc)
            )
            emit_detector_event(
                "command.single_request_rejected", 
                command=command_name, 
                command_id=command_id, 
                reason=str(exc)
            )
            return jsonify({"executed": False, "command": command_name, "error": str(exc)}), 400

        request_payload = {
            "device_id": DEVICE_ID,
            "device_profile": DEVICE_PROFILE,
            "command_id": command_id,
            "simulated": True,
        }
        try:
            target_response = post_json(target_url, request_payload, token=SIMULATION_TOKEN)
            target_response.raise_for_status()
            target_payload = target_response.json()
        except Exception as exc:
            log_event(
                logger, 
                "command.single_request_failed", 
                device_id=DEVICE_ID, 
                command_id=command_id, 
                target_url=target_url, 
                reason=str(exc)
            )
            emit_detector_event(
                "command.single_request_failed", 
                command=command_name, 
                command_id=command_id, 
                demo_target_url=target_url, 
                reason=str(exc)
            )
            return jsonify({
                "executed": False, 
                "command": command_name, 
                "target_url": target_url, 
                "error": "demo target request failed"}
            ), 502

        demo_request = {
            "command_id": command_id,
            "target_url": target_url,
            "target_status_code": target_response.status_code,
            "target_hit_count": target_payload.get("count"),
            "executed_at": now_iso(),
        }
        with state_lock:
            state["last_demo_request"] = demo_request

        log_event(
            logger, 
            "command.single_request_executed", 
            device_id=DEVICE_ID, 
            command_id=command_id, 
            target_url=target_url, 
            target_hit_count=target_payload.get("count")
        )
        emit_detector_event(
            "command.single_request_executed",
            command=command_name,
            command_id=command_id,
            demo_target_url=target_url,
            target_hit_count=target_payload.get("count"),
        )
        return jsonify({"executed": True, "command": command_name, "demo_request": demo_request})

    log_event(logger, "command.received", device_id=DEVICE_ID, command=command_name, command_id=command_id)
    emit_detector_event("command.received", command=command_name, command_id=command_id)
    return jsonify({"executed": True, "command": command_name, "result": "simulated acknowledgement"})

if __name__ == "__main__":
    log_event(
        logger,
        "service.started",
        port=5000,
        device_id=DEVICE_ID,
        device_profile=DEVICE_PROFILE,
        mitigation_enabled=MITIGATION_ENABLED,
        infection_allowed=INFECTION_ALLOWED,
        credential_usernames=[credential.username for credential in credentials],
    )
    app.run(host="0.0.0.0", port=5000, threaded=True)
