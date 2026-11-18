"""Tests for the attack result recorder and the metadata every result must carry (NFR-5)."""
import json

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


# ---------- Issue #21: results from a working tree with uncommitted changes ----------

def git(repo, *args):
    import subprocess
    subprocess.run(["git", *args], cwd=repo, check=True, capture_output=True,
                   env={"GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
                        "GIT_COMMITTER_EMAIL": "t@t", "HOME": str(repo), "PATH": __import__("os").environ["PATH"]})


@pytest.fixture
def repo(tmp_path):
    git(tmp_path, "init", "-q")
    (tmp_path / ".gitignore").write_text("results/\n")
    (tmp_path / "code.py").write_text("x = 1\n")
    git(tmp_path, "add", ".")
    git(tmp_path, "commit", "-q", "-m", "first")
    return tmp_path


def test_clean_tree_is_not_dirty(repo):
    assert results.working_tree_dirty(repo) is False
    assert len(results.commit_hash(repo)) == 40


def test_modified_file_makes_the_tree_dirty(repo):
    (repo / "code.py").write_text("x = 2\n")
    assert results.working_tree_dirty(repo) is True


def test_new_file_makes_the_tree_dirty_but_ignored_files_do_not(repo):
    (repo / "results").mkdir()
    (repo / "results" / "attack_results.jsonl").write_text("{}\n")
    assert results.working_tree_dirty(repo) is False   # results are ignored, as in the project
    (repo / "new_attack.py").write_text("y = 1\n")
    assert results.working_tree_dirty(repo) is True


def test_outside_a_repository_dirty_is_unknown(tmp_path):
    assert results.working_tree_dirty(tmp_path) is None


def test_every_result_records_the_dirty_field(tmp_path):
    row = results.record_attack("x", "password", "blocked", "blocked", directory=tmp_path)
    assert row["dirty"] in (True, False, None)
