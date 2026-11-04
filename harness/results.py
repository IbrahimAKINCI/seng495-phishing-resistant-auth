"""Records attack outcomes and the information every result file must carry (NFR-5):
commit hash, parameters and machine specification."""
import json
import os
import platform
import subprocess
from datetime import datetime, timezone
from pathlib import Path

OUTCOMES = {"blocked", "succeeded", "not_applicable", "error"}
RESULTS_DIR = Path(os.environ.get("HARNESS_RESULTS_DIR", "results"))
ATTACK_FILE = "attack_results.jsonl"


def commit_hash() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def machine_spec() -> dict:
    return {
        "os": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def run_metadata(parameters: dict | None = None) -> dict:
    return {"commit": commit_hash(), "parameters": parameters or {}, "machine": machine_spec()}


def record_attack(attack: str, method: str, expected: str, actual: str, detail: str = "",
                  directory: Path | None = None) -> dict:
    """Append one attack result. `expected` is the outcome written down before the test
    ran (docs/threat_model.md); `actual` is what the test observed."""
    for value in (expected, actual):
        if value not in OUTCOMES:
            raise ValueError(f"unknown outcome {value!r}")
    row = {
        "time": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "attack": attack,
        "method": method,
        "expected": expected,
        "actual": actual,
        "confirmed": expected == actual,
        "detail": detail,
        **run_metadata(),
    }
    directory = Path(directory) if directory else RESULTS_DIR
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / ATTACK_FILE).open("a", encoding="utf-8") as f:
        f.write(json.dumps(row) + "\n")
    return row
