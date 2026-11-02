"""The two log formats from Section 8 of the requirements. Module C reads these files.

Friction log (results/friction.jsonl), one line per client event:
    run_id, flow, method, event (flow_start | step | keystroke | error | flow_end), t_ms, detail

Server timing log (results/server_timing.jsonl), one line per authentication request:
    request_id, endpoint, method, status, server_ms
"""
import json
import os
import secrets
import threading
import time
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, Request
from pydantic import BaseModel, Field
from starlette.middleware.base import BaseHTTPMiddleware

RESULTS_DIR = Path(os.environ.get("AUTH_RESULTS_DIR", "results"))
FRICTION_FILE = "friction.jsonl"
TIMING_FILE = "server_timing.jsonl"

_lock = threading.Lock()


def _append(name: str, rows: list[dict]) -> None:
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    with _lock, (RESULTS_DIR / name).open("a", encoding="utf-8") as f:
        for row in rows:
            f.write(json.dumps(row) + "\n")


# ---------- friction events from the client ----------

class FrictionEvent(BaseModel):
    run_id: str = Field(max_length=64)
    flow: str = Field(max_length=64)          # e.g. "login", "register", "totp_enrol"
    method: str = Field(max_length=32)        # "password", "password+totp", "passkey", "recovery"
    event: Literal["flow_start", "step", "keystroke", "error", "flow_end"]
    t_ms: float
    detail: str = Field(default="", max_length=128)


class FrictionBatch(BaseModel):
    events: list[FrictionEvent] = Field(max_length=500)


router = APIRouter(prefix="/metrics", tags=["Module B - friction log"])


@router.post("/events", status_code=204)
def friction_events(batch: FrictionBatch):
    _append(FRICTION_FILE, [e.model_dump() for e in batch.events])


# ---------- server timing ----------

TIMED_PREFIXES = ("/auth/", "/session/login/", "/recovery/start", "/recovery/complete")


def _auth_method(path: str) -> str:
    if "passkey" in path or "webauthn" in path:
        return "passkey"
    if "totp" in path:
        return "totp"
    if "recovery" in path:
        return "recovery"
    if "password" in path or "register" in path:
        return "password"
    return "other"


class ServerTimingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        if not request.url.path.startswith(TIMED_PREFIXES):
            return await call_next(request)
        started = time.perf_counter()
        response = await call_next(request)
        _append(TIMING_FILE, [{
            "request_id": secrets.token_hex(8),
            "endpoint": request.url.path,
            "method": _auth_method(request.url.path),
            "status": response.status_code,
            "server_ms": round((time.perf_counter() - started) * 1000, 3),
        }])
        return response
