"""Readers for the two log files of Section 8, and the per-run measurements.

friction.jsonl       run_id, flow, method, event, t_ms, detail
server_timing.jsonl  request_id, endpoint, method, server_ms  (the service also writes status)

Module C reads these files; it never imports the code that writes them."""
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

FRICTION_EVENTS = {"flow_start", "step", "keystroke", "error", "flow_end"}
FRICTION_FIELDS = {"run_id": str, "flow": str, "method": str, "event": str, "t_ms": (int, float)}
TIMING_FIELDS = {"request_id": str, "endpoint": str, "method": str, "server_ms": (int, float)}


class LogFormatError(ValueError):
    pass


def read_jsonl(path: Path) -> list[dict]:
    path = Path(path)
    if not path.exists():
        return []
    rows = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if line.strip():
            try:
                rows.append(json.loads(line))
            except json.JSONDecodeError as exc:
                raise LogFormatError(f"{path.name} line {number}: not JSON") from exc
    return rows


def _check(row: dict, fields: dict, name: str) -> None:
    for field, kind in fields.items():
        if field not in row:
            raise LogFormatError(f"{name}: missing field {field!r}")
        if isinstance(row[field], bool) or not isinstance(row[field], kind):
            raise LogFormatError(f"{name}: field {field!r} has the wrong type")


def check_friction_row(row: dict) -> None:
    _check(row, FRICTION_FIELDS, "friction")
    if row["event"] not in FRICTION_EVENTS:
        raise LogFormatError(f"friction: unknown event {row['event']!r}")


def check_timing_row(row: dict) -> None:
    _check(row, TIMING_FIELDS, "server_timing")


@dataclass(frozen=True)
class RunSummary:
    run_id: str
    flow: str
    method: str
    steps: int
    keystrokes: int
    errors: int
    elapsed_ms: float | None  # None when the run has no flow_end
    complete: bool            # has flow_start and flow_end, and no error


def friction_runs(rows: list[dict], extra_steps: dict[str, int] | None = None) -> list[RunSummary]:
    """One summary per run_id.

    steps       = number of `step` events (Section 7.1). Steps that happen outside the
                  browser (authenticator prompt, TOTP app) are added by the harness as
                  `step` events or passed in extra_steps = {run_id: count}.
    keystrokes  = number of `keystroke` events.
    elapsed_ms  = t_ms of flow_end minus t_ms of flow_start.
    """
    by_run: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        check_friction_row(row)
        by_run[row["run_id"]].append(row)
    extra_steps = extra_steps or {}
    result = []
    for run_id, events in by_run.items():
        starts = [e["t_ms"] for e in events if e["event"] == "flow_start"]
        ends = [e["t_ms"] for e in events if e["event"] == "flow_end"]
        errors = sum(e["event"] == "error" for e in events)
        elapsed = (ends[-1] - starts[0]) if starts and ends else None
        result.append(RunSummary(
            run_id=run_id,
            flow=events[0]["flow"],
            method=events[0]["method"],
            steps=sum(e["event"] == "step" for e in events) + extra_steps.get(run_id, 0),
            keystrokes=sum(e["event"] == "keystroke" for e in events),
            errors=errors,
            elapsed_ms=elapsed,
            complete=bool(starts and ends and errors == 0),
        ))
    return result


def server_times(rows: list[dict], endpoint: str | None = None, method: str | None = None,
                 ok_only: bool = True) -> list[float]:
    """server_ms values, optionally for one endpoint or method. By default only
    successful requests (status below 400, when the line has a status) are used."""
    values = []
    for row in rows:
        check_timing_row(row)
        if endpoint is not None and row["endpoint"] != endpoint:
            continue
        if method is not None and row["method"] != method:
            continue
        if ok_only and row.get("status", 200) >= 400:
            continue
        values.append(float(row["server_ms"]))
    return values
