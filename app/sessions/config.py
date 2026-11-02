"""Module B settings. Every number comes from the requirements specification."""
import os

COOKIE_NAME = "sid"
# FR-B1: Secure, HttpOnly, SameSite=Lax. Browsers treat http://localhost as secure,
# so Secure cookies work in local development too.
COOKIE_SECURE = os.environ.get("SESSION_COOKIE_SECURE", "1") == "1"
COOKIE_SAMESITE = "lax"

SESSION_ID_BYTES = 16       # 128 bits (FR-B1)
IDLE_TIMEOUT = 30 * 60      # FR-B2: 30 minutes without activity
ABSOLUTE_TIMEOUT = 12 * 3600  # FR-B2: 12 hours in total

CSRF_HEADER = "X-CSRF-Token"
SAFE_METHODS = {"GET", "HEAD", "OPTIONS"}
