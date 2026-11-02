"""FR-A11: the authentication policy file.

Semester 1 covers the login operation. Semester 2 adds the other operations
(add credential, remove credential, change recovery settings, account recovery).

Methods: "password" (password only), "password+totp", "passkey"."""
import json
from dataclasses import dataclass, field
from pathlib import Path

from . import config

ALL_METHODS = {"password", "password+totp", "passkey"}


@dataclass
class OperationRule:
    methods: set[str]
    require_uv: bool = False
    step_up: bool = False


@dataclass
class Policy:
    name: str
    operations: dict[str, OperationRule] = field(default_factory=dict)

    def rule(self, operation: str) -> OperationRule:
        return self.operations.get(operation, OperationRule(methods=set(ALL_METHODS)))

    def allows(self, operation: str, method: str) -> bool:
        return method in self.rule(operation).methods


def load_policy(path: Path | str = config.POLICY_PATH) -> Policy:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    ops = {}
    for op, rule in data.get("operations", {}).items():
        methods = set(rule["methods"])
        unknown = methods - ALL_METHODS
        if unknown:
            raise ValueError(f"Unknown methods in policy for '{op}': {unknown}")
        ops[op] = OperationRule(methods=methods, require_uv=rule.get("require_uv", False), step_up=rule.get("step_up", False))
    return Policy(name=data.get("name", Path(path).stem), operations=ops)


_current: Policy | None = None


def current_policy() -> Policy:
    global _current
    if _current is None:
        _current = load_policy()
    return _current


def set_policy(policy: Policy) -> None:
    """Used at start-up and by the tests that compare policies."""
    global _current
    _current = policy
