"""One place to read the time, so tests can move the clock forward
(FR-A7 blocks, challenge expiry, TOTP windows) without waiting."""
import time


class Clock:
    def __init__(self) -> None:
        self.offset = 0.0

    def now(self) -> float:
        return time.time() + self.offset

    def advance(self, seconds: float) -> None:
        self.offset += seconds

    def reset(self) -> None:
        self.offset = 0.0


clock = Clock()
