import os
import json
import threading
import time
from datetime import datetime, timezone
from typing import Any

from flask import Flask, jsonify

from common.config import env_bool, env_float, parse_credentials, safe_target_urls
from common.http import get_json, post_json
from common.logging import configure_logger, log_event


SERVICE_NAME = os.getenv("SERVICE_NAME", "bot-scanner")
SCANNER_ID = os.getenv("SCANNER_ID", SERVICE_NAME)
SIMULATION_TOKEN = os.getenv("SIMULATION_TOKEN", "local-simulation-token")
C2_URL = os.getenv("C2_URL", "http://c2:5000").rstrip("/")
DETECTOR_URL = os.getenv("DETECTOR_URL", "").rstrip("/")
TARGET_URLS = safe_target_urls(os.getenv("TARGET_URLS"), os.getenv("ALLOWED_TARGET_HOSTS"))
CREDENTIAL_DICTIONARY = parse_credentials(os.getenv("CREDENTIAL_DICTIONARY", "admin:admin,root:12345,user:user"))
AUTO_SCAN = env_bool("AUTO_SCAN", True)
RUN_ONCE = env_bool("RUN_ONCE", False)
SCAN_ONCE = env_bool("SCAN_ONCE", True)
SCAN_INTERVAL_SECONDS = env_float("SCAN_INTERVAL_SECONDS", 30.0)
COMMAND_POLL_INTERVAL_SECONDS = env_float("COMMAND_POLL_INTERVAL_SECONDS", 5.0)

app = Flask(__name__)
logger = configure_logger(SERVICE_NAME)
scan_lock = threading.Lock()
state: dict[str, Any] = {
    "scan_count": 0,
    "last_scan_at": None,
    "results": [],
    "registered_devices": {},
    "scanner_started_at": None,
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")

def emit_detector_event(event_type: str, **fields: Any) -> None:
    if not DETECTOR_URL:
        return
    payload = {"event_type": event_type, "source_service": SERVICE_NAME, "scanner_id": SCANNER_ID, **fields}
    try:
        post_json(f"{DETECTOR_URL}/events", payload, token=SIMULATION_TOKEN)
    except Exception as exc:
        log_event(logger, "detector.emit_failed", reason=str(exc), event_type=event_type)


def get_device_status(target_url: str) -> dict[str, Any]:
    response = get_json(f"{target_url}/status")
    response.raise_for_status()
    data = response.json()
    if not isinstance(data, dict):
        raise ValueError("device status was not a JSON object")
    return data


def register_with_c2(device_id: str, target_url: str) -> None:
    response = post_json(
        f"{C2_URL}/bots/register",
        {"device_id": device_id, "device_url": target_url, "scanner_id": SCANNER_ID},
        token=SIMULATION_TOKEN,
    )
    response.raise_for_status()
    with scan_lock:
        state["registered_devices"][device_id] = target_url
    log_event(logger, "scanner.c2_registered", device_id=device_id, target_url=target_url)


def scan_target(target_url: str) -> dict[str, Any]:
    """
    Function that attempts to authenticate to the target using a 
    credential dictionary, then infect if successful.
    """
    result: dict[str, Any] = {
        "target_url": target_url,
        "started_at": now_iso(),
        "credential_attempts": 0,
        "authenticated": False,
        "infected": False,
        "blocked": False,
        "errors": [],
    }
    try:
        status = get_device_status(target_url)
        result["device_id"] = status.get("device_id")
        result["device_profile"] = status.get("device_profile")
        result["mitigation_enabled"] = status.get("mitigation_enabled")
    except Exception as exc:
        result["errors"].append(f"status failed: {exc}")
        log_event(logger, "scanner.target_unreachable", target_url=target_url, reason=str(exc))
        emit_detector_event("scanner.target_unreachable", target_url=target_url, reason=str(exc))
        return result

    for credential in CREDENTIAL_DICTIONARY:
        result["credential_attempts"] += 1
        log_event(
            logger, 
            "scanner.credential_attempt", 
            target_url=target_url, username=credential.username
        )
        emit_detector_event(
            "scanner.credential_attempt", 
            target_url=target_url, 
            device_id=result.get("device_id"), 
            username=credential.username
        )

        try:
            login_response = post_json(
                f"{target_url}/login",
                {"username": credential.username, "password": credential.password, "scanner_id": SCANNER_ID},
            )
        except Exception as exc:
            result["errors"].append(f"login failed: {exc}")
            continue

        if login_response.status_code == 423:
            result["blocked"] = True
            log_event(logger, "scanner.locked_out", target_url=target_url, username=credential.username)
            break
        if login_response.status_code != 200:
            continue

        payload = login_response.json()
        if not payload.get("authenticated"):
            continue

        result["authenticated"] = True
        device_id = str(payload.get("device_id") or result.get("device_id") or target_url)
        log_event(
            logger, 
            "scanner.weak_credential_found", 
            target_url=target_url, 
            device_id=device_id, 
            username=credential.username
        )
        emit_detector_event(
            "scanner.weak_credential_found", 
            target_url=target_url, 
            device_id=device_id, 
            username=credential.username
        )

        infect_response = post_json(
            f"{target_url}/infect",
            {"scanner_id": SCANNER_ID, "credential": credential.redacted},
            token=SIMULATION_TOKEN,
        )
        infect_response.raise_for_status()
        infect_payload = infect_response.json()
        result["infected"] = bool(infect_payload.get("infected"))
        result["blocked"] = bool(infect_payload.get("blocked"))
        if result["infected"]:
            register_with_c2(device_id, target_url)
        break

    if not result["infected"]:
        if result["blocked"]:
            reason = "locked_out"
        elif result["authenticated"]:
            reason = "infection_blocked"
        else:
            reason = "credentials_rejected"
        log_event(
            logger,
            "scanner.compromise_failed",
            target_url=target_url,
            device_id=result.get("device_id"),
            device_profile=result.get("device_profile"),
            credential_attempts=result["credential_attempts"],
            reason=reason,
        )
        emit_detector_event(
            "scanner.compromise_failed",
            target_url=target_url,
            device_id=result.get("device_id"),
            device_profile=result.get("device_profile"),
            credential_attempts=result["credential_attempts"],
            reason=reason,
        )

    result["completed_at"] = now_iso()
    return result


def run_scan() -> list[dict[str, Any]]:
    """Function that runs a scan of all target URLs."""
    with scan_lock:
        state["scan_count"] += 1
        state["last_scan_at"] = now_iso()
    log_event(
        logger, 
        "scanner.scan_started", 
        target_count=len(TARGET_URLS)
    )
    emit_detector_event("scanner.scan_started", target_count=len(TARGET_URLS))
    results = [scan_target(target_url) for target_url in TARGET_URLS]
    with scan_lock:
        state["results"] = results
    log_event(
        logger, 
        "scanner.scan_completed", 
        target_count=len(TARGET_URLS), 
        infected=sum(1 for item in results if item.get("infected"))
    )
    emit_detector_event(
        "scanner.scan_completed", 
        target_count=len(TARGET_URLS), 
        infected=sum(1 for item in results if item.get("infected"))
    )
    return results


def command_poll_loop() -> None:
    """
    Background thread function that continuously polls the C2 for 
    commands for registered devices and dispatches them.
    """
    while True:
        time.sleep(COMMAND_POLL_INTERVAL_SECONDS)
        with scan_lock:
            registered = dict(state["registered_devices"])
        for device_id, target_url in registered.items():
            try:
                response = get_json(f"{C2_URL}/commands/{device_id}", token=SIMULATION_TOKEN)
                response.raise_for_status()
                commands = response.json().get("commands", [])
            except Exception as exc:
                log_event(
                    logger, 
                    "scanner.command_poll_failed", 
                    device_id=device_id, 
                    reason=str(exc)
                )
                continue
            for command in commands:
                try:
                    post_json(f"{target_url}/command", command, token=SIMULATION_TOKEN).raise_for_status()
                    log_event(
                        logger, 
                        "scanner.command_dispatched", 
                        device_id=device_id, 
                        command=command.get("command"), 
                        command_id=command.get("command_id")
                    )
                except Exception as exc:
                    log_event(
                        logger, 
                        "scanner.command_dispatch_failed", 
                        device_id=device_id, 
                        command_id=command.get("command_id"), 
                        reason=str(exc)
                    )


def auto_scan_loop() -> None:
    state["scanner_started_at"] = now_iso()
    time.sleep(3.0)
    while True:
        try:
            run_scan()
        except Exception as exc:
            log_event(logger, "scanner.scan_failed", reason=str(exc))
        if SCAN_ONCE:
            return
        time.sleep(SCAN_INTERVAL_SECONDS)


@app.get("/health")
def health() -> Any:
    return jsonify({"status": "ok", "service": SERVICE_NAME, "scanner_id": SCANNER_ID})


@app.get("/state")
def current_state() -> Any:
    with scan_lock:
        return jsonify(state)


@app.post("/scan")
def trigger_scan() -> Any:
    results = run_scan()
    return jsonify({"results": results})


if __name__ == "__main__":
    log_event(
        logger,
        "service.started",
        port=5000,
        scanner_id=SCANNER_ID,
        target_urls=TARGET_URLS,
        credential_usernames=[credential.username for credential in CREDENTIAL_DICTIONARY],
        auto_scan=AUTO_SCAN,
        run_once=RUN_ONCE,
    )
    if RUN_ONCE:
        scan_results = run_scan()
        summary = {
            "infected_devices": [item.get("device_id") for item in scan_results if item.get("infected")],
            "failed_targets": [
                {
                    "device_id": item.get("device_id"),
                    "device_profile": item.get("device_profile"),
                    "target_url": item.get("target_url"),
                    "credential_attempts": item.get("credential_attempts"),
                    "blocked": item.get("blocked"),
                }
                for item in scan_results
                if not item.get("infected")
            ],
            "results": scan_results,
        }
        print(json.dumps(summary, indent=2, sort_keys=True))
        raise SystemExit(0)

    threading.Thread(target=command_poll_loop, daemon=True).start()
    if AUTO_SCAN:
        threading.Thread(target=auto_scan_loop, daemon=True).start()
    app.run(host="0.0.0.0", port=5000, threaded=True)
