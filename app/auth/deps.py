"""The link between Module A and Module B.

Module B owns sessions. It tells Module A who is logged in by overriding this
dependency in the main app:

    app.dependency_overrides[get_current_user_id] = module_b_session_user_id

Until then every protected route answers 401."""
from fastapi import HTTPException


def get_current_user_id() -> int:
    raise HTTPException(status_code=401, detail="Not authenticated.")
