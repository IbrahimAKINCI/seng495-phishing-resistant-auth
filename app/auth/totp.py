"""FR-A3 / FR-A4: TOTP enrolment and verification, NFR-2: secret encrypted at rest."""
import base64
import hmac
import io
import os

import pyotp
import qrcode
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config


def new_secret() -> str:
    # 20 random bytes = 160 bits, the length RFC 4226 recommends
    return base64.b32encode(os.urandom(20)).decode("ascii")


def encrypt_secret(secret: str) -> bytes:
    nonce = os.urandom(12)
    return nonce + AESGCM(config.totp_encryption_key()).encrypt(nonce, secret.encode(), b"totp")


def decrypt_secret(blob: bytes) -> str:
    nonce, ciphertext = blob[:12], blob[12:]
    return AESGCM(config.totp_encryption_key()).decrypt(nonce, ciphertext, b"totp").decode()


def provisioning_uri(secret: str, username: str) -> str:
    return pyotp.TOTP(secret, digits=config.TOTP_DIGITS, interval=config.TOTP_PERIOD).provisioning_uri(
        name=username, issuer_name=config.TOTP_ISSUER
    )


def qr_png_base64(uri: str) -> str:
    img = qrcode.make(uri)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode("ascii")


def code_at_step(secret: str, step: int) -> str:
    return pyotp.TOTP(secret, digits=config.TOTP_DIGITS, interval=config.TOTP_PERIOD).at(step * config.TOTP_PERIOD)


def match_step(secret: str, code: str, now: float, last_used_step: int) -> int | None:
    """Returns the time step the code belongs to, or None if it is not accepted.

    A code is accepted only in its own 30-second window or one window either side,
    and only if its step is newer than the last accepted step, so each code works once."""
    if not (code.isdigit() and len(code) == config.TOTP_DIGITS):
        return None
    current = int(now // config.TOTP_PERIOD)
    for step in range(current - config.TOTP_WINDOW, current + config.TOTP_WINDOW + 1):
        if hmac.compare_digest(code_at_step(secret, step), code):
            return step if step > last_used_step else None
    return None
