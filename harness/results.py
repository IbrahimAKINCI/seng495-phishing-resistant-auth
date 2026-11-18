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


def commit_hash(cwd: Path | None = None) -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True, timeout=10, cwd=cwd)
        return out.stdout.strip() or "unknown"
    except (OSError, subprocess.SubprocessError):
        return "unknown"


def working_tree_dirty(cwd: Path | None = None) -> bool | None:
    """True when the working tree has changes that are not committed (modified, staged or
    new files that are not ignored), False when it is clean, None when git cannot tell.

    Issue #21: a result from a dirty tree names a commit that does not contain the code
    that produced it, so it cannot be reproduced from that commit (NFR-5)."""
    try:
        out = subprocess.run(["git", "status", "--porcelain"], capture_output=True, text=True, timeout=10, cwd=cwd)
    except (OSError, subprocess.SubprocessError):
        return None
    if out.returncode != 0:
        return None
    return bool(out.stdout.strip())


def machine_spec() -> dict:
    return {
        "os": platform.platform(),
        "processor": platform.processor(),
        "cpu_count": os.cpu_count(),
        "python": platform.python_version(),
    }


def run_metadata(parameters: dict | None = None) -> dict:
    return {"commit": commit_hash(), "dirty": working_tree_dirty(), "parameters": parameters or {},
            "machine": machine_spec()}


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
