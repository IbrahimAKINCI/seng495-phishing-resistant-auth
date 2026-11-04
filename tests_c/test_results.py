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
