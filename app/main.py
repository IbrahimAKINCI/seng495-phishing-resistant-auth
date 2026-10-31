"""Entry point of the authentication service.

Run locally with:
    uvicorn app.main:app --reload
"""

from fastapi import FastAPI

app = FastAPI(
    title="Phishing-Resistant Authentication Service",
    description="SENG 495/496 senior design project.",
    version="0.1.0",
)


@app.get("/health")
def health() -> dict[str, str]:
    """Liveness check used to verify that the service skeleton is running."""
    return {"status": "ok"}
