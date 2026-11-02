class AuthError(Exception):
    """An error the API turns into an HTTP response with a safe, generic message."""

    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


LOGIN_FAILED = "Login failed."
REGISTRATION_FAILED = "Registration failed."
TOO_MANY_ATTEMPTS = "Too many failed attempts. Try again later."


def login_failed() -> AuthError:
    return AuthError(401, LOGIN_FAILED)


def too_many() -> AuthError:
    return AuthError(429, TOO_MANY_ATTEMPTS)
