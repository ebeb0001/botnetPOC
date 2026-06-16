import pathlib
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
DISALLOWED_PATTERNS = [
    "scapy",
    "nmap",
    "masscan",
    "subprocess.Popen",
    "os.system",
    "socket.socket",
    "SYN",
    "UDP flood",
]


def run(command: list[str]) -> None:
    print("+", " ".join(command))
    subprocess.run(command, cwd=ROOT, check=True)


def compile_python() -> None:
    run([sys.executable, "-m", "compileall", "-q", "common", "services", "scripts"])


def compose_config() -> None:
    run(["docker", "compose", "-f", "docker-compose.yml", "config", "--quiet"])
    run(["docker", "compose", "-f", "docker-compose.yml", "-f", "docker-compose.mitigated.yml", "config", "--quiet"])


def static_safety_scan() -> None:
    findings: list[str] = []
    for path in list((ROOT / "common").rglob("*.py")) + list((ROOT / "services").rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for pattern in DISALLOWED_PATTERNS:
            if pattern in text:
                findings.append(f"{path.relative_to(ROOT)} contains {pattern!r}")
    if findings:
        raise SystemExit("Disallowed safety pattern found:\n" + "\n".join(findings))


def main() -> None:
    compile_python()
    static_safety_scan()
    compose_config()
    print("Verification passed.")


if __name__ == "__main__":
    main()
