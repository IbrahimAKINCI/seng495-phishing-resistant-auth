"""Tests for the attack result recorder and the metadata every result must carry (NFR-5)."""
import json
import subprocess

import pytest

from harness import results


def test_record_attack_writes_one_line_with_metadata(tmp_path):
    row = results.record_attack("totp_replay", "password+totp", "blocked", "blocked", "second use refused",
                                directory=tmp_path)
    lines = (tmp_path / results.ATTACK_FILE).read_text().splitlines()
    assert len(lines) == 1
    stored = json.loads(lines[0])
    assert stored == row
    assert stored["confirmed"] is True
    for key in ("commit", "parameters", "machine", "time"):
        assert key in stored
    assert {"os", "cpu_count", "python"} <= set(stored["machine"])


def test_a_refuted_expectation_is_recorded_as_not_confirmed(tmp_path):
    row = results.record_attack("x", "password", "blocked", "succeeded", directory=tmp_path)
    assert row["confirmed"] is False


def test_results_are_appended_not_overwritten(tmp_path):
    for _ in range(3):
        results.record_attack("x", "password", "blocked", "blocked", directory=tmp_path)
    assert len((tmp_path / results.ATTACK_FILE).read_text().splitlines()) == 3


def test_unknown_outcome_is_rejected(tmp_path):
    with pytest.raises(ValueError):
        results.record_attack("x", "password", "blocked", "worked", directory=tmp_path)
    assert not (tmp_path / results.ATTACK_FILE).exists()


def test_run_metadata_carries_parameters():
    meta = results.run_metadata({"runs": 20, "seed": 495})
    assert meta["parameters"] == {"runs": 20, "seed": 495}
    assert meta["commit"]


# ---------- Issue #21: a result must say when its code was not fully committed ----------

def git(repo, *args):
    subprocess.run(["git", "-c", "user.name=t", "-c", "user.email=t@example.com", "-c", "commit.gpgsign=false",
                    *args], cwd=repo, check=True, capture_output=True)


@pytest.fixture
def repo(tmp_path):
    """A temporary git repository with one commit and a .gitignore for *.log files."""
    git(tmp_path, "init", "-q")
    (tmp_path / "a.txt").write_text("one")
    (tmp_path / ".gitignore").write_text("*.log\n")
    git(tmp_path, "add", "a.txt", ".gitignore")
    git(tmp_path, "commit", "-q", "-m", "first")
    return tmp_path


def test_a_clean_tree_is_not_dirty(repo):
    assert results.working_tree_dirty(repo) is False


def test_a_changed_tracked_file_makes_the_tree_dirty(repo):
    (repo / "a.txt").write_text("two")
    assert results.working_tree_dirty(repo) is True


def test_a_new_untracked_file_makes_the_tree_dirty(repo):
    (repo / "new_test.py").write_text("x = 1")
    assert results.working_tree_dirty(repo) is True


def test_an_ignored_file_does_not_make_the_tree_dirty(repo):
    (repo / "run.log").write_text("output")      # results files are ignored the same way
    assert results.working_tree_dirty(repo) is False


def test_outside_a_repository_the_tree_counts_as_dirty_and_the_commit_is_unknown(tmp_path):
    assert results.working_tree_dirty(tmp_path) is True
    assert results.commit_hash(tmp_path) == "unknown"


def test_metadata_records_the_commit_and_the_dirty_state(repo):
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=repo, capture_output=True, text=True).stdout.strip()
    assert results.run_metadata(cwd=repo)["commit"] == head
    assert results.run_metadata(cwd=repo)["dirty"] is False
    (repo / "a.txt").write_text("two")
    assert results.run_metadata(cwd=repo)["dirty"] is True
