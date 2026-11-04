"""NFR-7: Module C uses only the HTTP API and the log files. It must not import code
from Module A or B (the `app` package). This test reads the source of Module C and
fails if any file imports from `app`."""
import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MODULE_C_DIRS = ["harness", "attacks", "tests_c", "tests_e2e"]


def imported_roots(path: Path) -> set[str]:
    tree = ast.parse(path.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def test_module_c_does_not_import_the_service_packages():
    offenders = []
    checked = 0
    for folder in MODULE_C_DIRS:
        for path in (ROOT / folder).rglob("*.py"):
            checked += 1
            if {"app", "tests", "tests_b"} & imported_roots(path):
                offenders.append(str(path.relative_to(ROOT)))
    assert checked > 0
    assert offenders == []


def test_the_check_detects_a_forbidden_import(tmp_path):
    bad = tmp_path / "bad.py"
    bad.write_text("from app.auth import service\nimport tests.conftest\n", encoding="utf-8")
    assert {"app", "tests"} <= imported_roots(bad)
