"""Entry point of the authentication service.

Module A: app/auth. Module B: app/sessions, app/recovery, app/friction and the web
client in web/.

Run locally with:
    uvicorn app.main:app --reload --port 8001    then open http://localhost:8001
"""
from pathlib import Path

from fastapi import FastAPI, Header, HTTPException
from fastapi.staticfiles import StaticFiles

from app.auth.db import init_db
from app.auth.deps import get_current_user_id
from app.auth.errors import AuthError
from app.auth.router import auth_error_handler
from app.auth.router import router as auth_router
from app.friction.logs import ServerTimingMiddleware
from app.friction.logs import router as friction_router
from app.recovery import models as _recovery_models  # noqa: F401  (registers the tables)
from app.recovery.router import router as recovery_router
from app.sessions import models as _session_models  # noqa: F401
from app.sessions.deps import session_user_id
from app.sessions.router import router as session_router

WEB_DIR = Path(__file__).resolve().parents[1] / "web"


def create_app(dev_user_header: bool = False) -> FastAPI:
    app = FastAPI(
        title="Phishing-Resistant Authentication Service",
        description="SENG 495/496 senior design project.",
        version="0.1.0",
    )
    init_db()
    app.add_exception_handler(AuthError, auth_error_handler)
    app.add_middleware(ServerTimingMiddleware)

    app.include_router(auth_router)        # Module A
    app.include_router(session_router)     # Module B
    app.include_router(recovery_router)    # Module B
    app.include_router(friction_router)    # Module B

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness check used to verify that the service skeleton is running."""
        return {"status": "ok"}

    if dev_user_header:
        # Only for Module A's unit tests: the user comes from an X-Dev-User header
        # instead of a session, so Module A can be tested on its own.
        def dev_user(x_dev_user: int | None = Header(default=None)) -> int:
            if x_dev_user is None:
                raise HTTPException(status_code=401, detail="Not authenticated.")
            return x_dev_user

        app.dependency_overrides[get_current_user_id] = dev_user
    else:
        # The connection between A and B (Section 8): Module A's protected routes
        # get the logged-in user from Module B's session.
        app.dependency_overrides[get_current_user_id] = session_user_id

    # The web client (FR-B5), served last so it never hides an API route
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
    return app


app = create_app()
