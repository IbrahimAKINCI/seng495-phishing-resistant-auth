"""FR-A2: password hashing with Argon2id."""
from argon2 import PasswordHasher, Type
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from . import config

hasher = PasswordHasher(
    time_cost=config.ARGON2_TIME_COST,
    memory_cost=config.ARGON2_MEMORY_KIB,
    parallelism=config.ARGON2_PARALLELISM,
    hash_len=config.ARGON2_HASH_LEN,
    salt_len=config.ARGON2_SALT_LEN,
    type=Type.ID,
)

# Used when the username does not exist, so the response takes as long as for a
# real account and timing does not reveal which accounts exist (NFR-1, FR-C9).
_DUMMY_HASH = hasher.hash("dummy-password-for-timing")


def hash_password(password: str) -> str:
    return hasher.hash(password)


def verify_password(stored_hash: str | None, password: str) -> bool:
    if stored_hash is None:
        _burn_time(password)
        return False
    try:
        return hasher.verify(stored_hash, password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False


def _burn_time(password: str) -> None:
    try:
        hasher.verify(_DUMMY_HASH, password + "x")
    except VerifyMismatchError:
        pass


def needs_rehash(stored_hash: str) -> bool:
    return hasher.check_needs_rehash(stored_hash)


def check_password_rules(password: str) -> str | None:
    """Returns an error message, or None if the password is acceptable."""
    if len(password) < config.PASSWORD_MIN_LENGTH:
        return f"Password must be at least {config.PASSWORD_MIN_LENGTH} characters."
    if len(password) > config.PASSWORD_MAX_LENGTH:
        return f"Password must be at most {config.PASSWORD_MAX_LENGTH} characters."
    return None
