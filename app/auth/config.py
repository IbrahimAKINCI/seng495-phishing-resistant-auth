"""Module A settings. Every number here comes from the requirements specification."""
import base64
import os
from pathlib import Path

INSTANCE_DIR = Path(os.environ.get("AUTH_INSTANCE_DIR", "instance"))

# DATABASE_URL is the team setting from .env.example; AUTH_DATABASE_URL overrides it (tests)
DATABASE_URL = os.environ.get("AUTH_DATABASE_URL") or os.environ.get("DATABASE_URL") or "sqlite:///./app.db"

# FR-A2: Argon2id, OWASP minimum settings
ARGON2_MEMORY_KIB = 19456  # 19 MiB
ARGON2_TIME_COST = 2
ARGON2_PARALLELISM = 1
ARGON2_HASH_LEN = 32
ARGON2_SALT_LEN = 16

PASSWORD_MIN_LENGTH = 12  # ASVS Level 2, Authentication chapter
PASSWORD_MAX_LENGTH = 128

# FR-A3 / FR-A4: TOTP (RFC 6238)
TOTP_DIGITS = 6
TOTP_PERIOD = 30
TOTP_WINDOW = 1  # accept one window either side
TOTP_ISSUER = "SENG Auth Service"

# FR-A7: rate limits
RATE_WINDOW_SECONDS = 15 * 60
RATE_BLOCK_SECONDS = 15 * 60
RATE_MAX_FAILURES_ACCOUNT = 5
RATE_MAX_FAILURES_IP = 20

# FR-A5 / Section 4.2: WebAuthn
RP_ID = os.environ.get("AUTH_RP_ID", "localhost")
RP_NAME = "SENG Auth Service"
# The team runs the service on port 8001 (README). Passkeys only work if this matches
# the address in the browser exactly.
EXPECTED_ORIGIN = os.environ.get("AUTH_EXPECTED_ORIGIN", "http://localhost:8001")
CHALLENGE_TTL_SECONDS = 5 * 60  # check 3

# Pending login after a correct password, waiting for the TOTP code
PENDING_LOGIN_TTL_SECONDS = 5 * 60

# FR-A11: authentication policy file
POLICY_PATH = Path(os.environ.get("AUTH_POLICY_PATH", Path(__file__).resolve().parents[2] / "policy" / "default.json"))


def totp_encryption_key() -> bytes:
    """NFR-2: TOTP secrets are encrypted with AES-GCM. The key comes from the
    TOTP_ENC_KEY environment variable (base64, 32 bytes). For local development
    a key file is created in the instance folder, which is not committed."""
    env = os.environ.get("TOTP_ENC_KEY")
    if env:
        key = base64.b64decode(env)
    else:
        INSTANCE_DIR.mkdir(parents=True, exist_ok=True)
        key_file = INSTANCE_DIR / "totp.key"
        if not key_file.exists():
            key_file.write_bytes(base64.b64encode(os.urandom(32)))
        key = base64.b64decode(key_file.read_bytes())
    if len(key) != 32:
        raise RuntimeError("TOTP_ENC_KEY must be 32 bytes (base64 encoded)")
    return key
