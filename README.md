# Safe Docker Mirai Simulation

This repository is an academic, Docker-only simulation of Mirai-style botnet behavior. It demonstrates weak IoT credentials, fixed-scope scanning, simulated infection, C2 registration, safe command distribution, detection, and mitigation without implementing malware.

## Components

| Component | Purpose |
| --- | --- |
| `iot-device` | Flask service that models an IoT camera, router, DVR, or smart light. Infection is only an in-memory boolean. |
| `scanner` | One-shot scanner constrained to `TARGET_URLS` and `ALLOWED_TARGET_HOSTS`; it only talks to named Docker services. |
| `c2-server` | Registers simulated bots and distributes only allowlisted safe commands. |
| `target_server` | Internal demo target that records one harmless request per infected device. |
| `detector` | Ingests JSON events and raises alerts for scanning, compromise, infection, C2 registration, commands, and mitigation. |

## Scenario Files

`docker-compose.yml` is the vulnerable scenario. It includes three weak-credential devices and one strong-credential device:

| Device | Credentials | Expected scanner result |
| --- | --- | --- |
| `camera-01` | `admin:admin` | infected |
| `router-01` | `root:12345` | infected |
| `dvr-01` | `user:user` | infected |
| `light-strong-01` | strong credentials not in the scanner dictionary | compromise fails |

## Step-By-Step Demonstration

```bash
# Start vulnerable scenario
docker compose up -d --build

# Run scanner
docker compose run --rm scanner

# Verify infected bots
curl http://localhost:5000/bots

# Verify target has no hits yet
curl http://localhost:8080/hits

# Send safe command
curl -X POST http://localhost:5000/command -H "Content-Type: application/json" -d '{"command":"single_request","target":"http://target_server:8000/"}'

# Verify bots contacted target
curl http://localhost:8080/hits

# Stop vulnerable scenario
docker compose down -v
```

Expected vulnerable result:

- `camera-01`, `router-01`, and `dvr-01` become bots.
- `light-strong-01` resists infection because its credentials are not in the scanner dictionary.
- The scanner output includes `light-strong-01` under `failed_targets` and emits `scanner.compromise_failed`.
- `docker compose logs light` shows failed login attempts for the strong device.
- `/bots` returns only the infected weak-credential devices.
- `/hits` returns `0` before `single_request` and increases after the safe command.


The command block above uses Bash-style curl quoting. In Windows PowerShell, use this equivalent for the safe command request:

```powershell
Invoke-RestMethod -Uri http://localhost:5000/command `
  -Method Post `
  -ContentType "application/json" `
  -Body '{"command":"single_request","target":"http://target_server:8000/"}'
```

If you want to use `curl.exe` from PowerShell, pipe the JSON body so PowerShell does not strip the embedded quotes:

```powershell
'{"command":"single_request","target":"http://target_server:8000/"}' |
  curl.exe -X POST "http://localhost:5000/command" `
    -H "Content-Type: application/json" `
    --data-binary "@-"
```

## Useful Endpoints

- C2: `http://localhost:5000/bots`
- Simplified local demo command endpoint: `POST http://localhost:5000/command`
- Detector alerts: `http://localhost:8081/alerts`
- Target hit count: `http://localhost:8080/hits`
- Target hit details: `http://localhost:8080/hit-log`

## Safety Controls

- Scanner targets are explicit URLs from `TARGET_URLS`.
- Every target hostname must appear in `ALLOWED_TARGET_HOSTS`.
- Target hostnames must be single-label Docker service names, not IP addresses or external DNS names.
- Target URLs must point to service roots, without credentials, paths, query strings, or fragments.
- Published Compose ports are bound to `127.0.0.1` only.
- The C2 accepts only the allowlisted commands `collect_status`, `inventory`, `quarantine`, `rotate_credentials`, and `single_request`.
- The `single_request` demo command sends exactly one request per infected device to the internal `target_server` service.
- Device command handling only updates simulation state and returns acknowledgements.
- Detection uses JSON events.
