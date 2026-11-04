"""Starts the service as a separate process so the attack tests talk to it only over
HTTP, like a real attacker (and as NFR-7 requires: no imports from the service).

Each server gets its own temporary database, TOTP key and results folder, so tests
never touch a developer's local data. The server listens on 127.0.0.1 only."""
import base64
import os
import socket
import subprocess
import sys
import tempfile
import time
from contextlib import contextmanager
from dataclasses import dataclass
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class RunningService:
    base_url: str
    results_dir: Path


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@contextmanager
def running_service(policy: str = "default"):
    """Yields a RunningService. `policy` is the name of a file in policy/ (without .json)."""
    port = _free_port()
    base_url = f"http://127.0.0.1:{port}"
    with tempfile.TemporaryDirectory(prefix="attack-service-", ignore_cleanup_errors=True) as tmp:
        tmp_path = Path(tmp)
        env = {
            **os.environ,
            "AUTH_INSTANCE_DIR": str(tmp_path),
            "AUTH_DATABASE_URL": f"sqlite:///{(tmp_path / 'service.db').as_posix()}",
            "TOTP_ENC_KEY": base64.b64encode(os.urandom(32)).decode(),
            "AUTH_RP_ID": "127.0.0.1",
            "AUTH_EXPECTED_ORIGIN": base_url,
            "AUTH_RESULTS_DIR": str(tmp_path / "results"),
            "AUTH_POLICY_PATH": str(ROOT / "policy" / f"{policy}.json"),
            # the test client talks plain http, and a Secure cookie is not sent over http
            "SESSION_COOKIE_SECURE": "0",
        }
        log = (tmp_path / "server.log").open("w")
        proc = subprocess.Popen(
            [sys.executable, "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1", "--port", str(port)],
            cwd=ROOT, env=env, stdout=log, stderr=subprocess.STDOUT,
        )
        try:
            deadline = time.time() + 60
            while True:
                if proc.poll() is not None:
                    raise RuntimeError("service exited early:\n" + (tmp_path / "server.log").read_text())
                try:
                    if httpx.get(f"{base_url}/health", timeout=1).status_code == 200:
                        break
                except httpx.HTTPError:
                    pass
                if time.time() > deadline:
                    raise RuntimeError("service did not start within 60 seconds")
                time.sleep(0.2)
            yield RunningService(base_url=base_url, results_dir=tmp_path / "results")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            log.close()
