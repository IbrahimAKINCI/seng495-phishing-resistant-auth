"""Entry point of the authentication service.

Run locally with:
    uvicorn app.main:app --reload --port 8001
"""
from fastapi import FastAPI, Header, HTTPException

from app.auth.db import init_db
from app.auth.deps import get_current_user_id
from app.auth.errors import AuthError
from app.auth.router import auth_error_handler
from app.auth.router import router as auth_router


def create_app(dev_user_header: bool = False) -> FastAPI:
    app = FastAPI(
        title="Phishing-Resistant Authentication Service",
        description="SENG 495/496 senior design project.",
        version="0.1.0",
    )
    init_db()
    app.add_exception_handler(AuthError, auth_error_handler)
    app.include_router(auth_router)  # Module A

    @app.get("/health")
    def health() -> dict[str, str]:
        """Liveness check used to verify that the service skeleton is running."""
        return {"status": "ok"}

    if dev_user_header:
        # Only for Module A's unit tests: the user comes from an X-Dev-User header.
        # Module B replaces this with sessions (get_current_user_id override).
        def dev_user(x_dev_user: int | None = Header(default=None)) -> int:
            if x_dev_user is None:
                raise HTTPException(status_code=401, detail="Not authenticated.")
            return x_dev_user

        app.dependency_overrides[get_current_user_id] = dev_user

    return app


app = create_app()
