"""Known-answer tests for harness.stats. Every expected value below was worked out by
hand from the definition, not produced by running the code."""
import pytest

from harness import stats


def test_median_odd_and_even():
    assert stats.median([1, 2, 3, 4, 5]) == 3
    assert stats.median([5, 1, 4, 2, 3]) == 3          # order does not matter
    assert stats.median([1, 2, 3, 4]) == 2.5           # mean of the two middle values
    assert stats.median([7]) == 7


def test_median_is_not_moved_by_one_outlier():
    assert stats.median([10, 11, 12, 13, 5000]) == 12


def test_nearest_rank_p95_of_1_to_20_is_19():
    # rank = ceil(0.95 * 20) = 19, so the 19th smallest value
    assert stats.percentile(list(range(1, 21)), 95) == 19


def test_nearest_rank_other_percentiles():
    data = list(range(1, 21))
    assert stats.percentile(data, 50) == 10             # ceil(0.50 * 20) = 10
    assert stats.percentile(data, 100) == 20
    assert stats.percentile(data, 5) == 1               # ceil(0.05 * 20) = 1
    assert stats.percentile(data, 5.1) == 2             # ceil(1.02) = 2
    assert stats.percentile([42], 95) == 42
    assert stats.percentile([3, 1, 2], 95) == 3         # ceil(2.85) = 3


def test_percentile_rejects_bad_input():
    with pytest.raises(ValueError):
        stats.percentile([], 95)
    with pytest.raises(ValueError):
        stats.percentile([1, 2], 0)
    with pytest.raises(ValueError):
        stats.percentile([1, 2], 101)


def test_bootstrap_of_a_constant_sample_is_one_point():
    assert stats.bootstrap_ci_median([5.0] * 20) == (5.0, 5.0)


def test_bootstrap_of_two_values_spans_both():
    # A resample of two draws from {0, 10} has median 0, 5 or 10 with probabilities
    # 1/4, 1/2, 1/4. The lowest 2.5% are all 0 and the highest 2.5% are all 10.
    assert stats.bootstrap_ci_median([0, 10]) == (0, 10)


def test_bootstrap_interval_stays_inside_the_data_and_around_the_median():
    data = [float(x) for x in range(1, 21)]
    low, high = stats.bootstrap_ci_median(data)
    assert min(data) <= low <= stats.median(data) <= high <= max(data)


def test_bootstrap_is_repeatable_with_the_same_seed():
    data = [12.1, 9.8, 15.3, 11.0, 10.4, 13.7, 9.9, 14.2, 10.8, 12.6]
    assert stats.bootstrap_ci_median(data, seed=7) == stats.bootstrap_ci_median(data, seed=7)


def test_more_spread_gives_a_wider_interval():
    tight = [10.0, 10.1, 9.9, 10.0, 10.2, 9.8, 10.0, 10.1, 9.9, 10.0]
    wide = [2.0, 18.0, 5.0, 15.0, 10.0, 1.0, 19.0, 8.0, 12.0, 10.0]
    t_low, t_high = stats.bootstrap_ci_median(tight)
    w_low, w_high = stats.bootstrap_ci_median(wide)
    assert (w_high - w_low) > (t_high - t_low)


def test_intervals_overlap():
    assert stats.intervals_overlap((1, 5), (4, 9))
    assert stats.intervals_overlap((1, 5), (5, 9))      # touching counts as overlap
    assert not stats.intervals_overlap((1, 5), (5.1, 9))


def test_two_clearly_different_samples_are_reported_as_different():
    fast = [10.0 + 0.1 * i for i in range(20)]
    slow = [100.0 + 0.1 * i for i in range(20)]
    assert stats.differ(fast, slow)
    assert not stats.differ(fast, fast)


def test_summary_of_1_to_20():
    s = stats.summarize([float(x) for x in range(1, 21)])
    assert (s.n, s.median, s.p95) == (20, 10.5, 19)
    assert s.ci_low <= s.median <= s.ci_high


# ---------- Issue #18: exact ranks ----------

@pytest.mark.parametrize("p, n, rank", [(28, 25, 7), (56, 25, 14), (14, 50, 7), (68, 75, 51), (7, 100, 7)])
def test_nearest_rank_cases_that_floating_point_got_wrong(p, n, rank):
    # rank = ceil(p * n / 100) worked out by hand: 28*25/100 = 7 exactly, and so on
    assert stats.nearest_rank(p, n) == rank
    assert stats.percentile(list(range(1, n + 1)), p) == rank


def test_nearest_rank_matches_integer_arithmetic_for_every_whole_p_and_n():
    for p in range(1, 101):
        for n in range(1, 201):
            assert stats.nearest_rank(p, n) == max(1, (p * n + 99) // 100), (p, n)


def test_decimal_percentiles_are_exact():
    assert stats.nearest_rank(5.1, 20) == 2      # 5.1 * 20 / 100 = 1.02 -> 2
    assert stats.nearest_rank(2.5, 10_000) == 250
    assert stats.nearest_rank(97.5, 10_000) == 9750


def test_bootstrap_bounds_are_ranks_250_and_9750_of_10000():
    import random
    from statistics import median

    data = [12.1, 9.8, 15.3, 11.0, 10.4, 13.7, 9.9, 14.2, 10.8, 12.6]
    # the same resampling, done here independently, then sorted
    rng = random.Random(stats.DEFAULT_SEED)
    medians = sorted(median(rng.choices(data, k=len(data))) for _ in range(10_000))
    assert stats.bootstrap_ci_median(data) == (medians[250 - 1], medians[9750 - 1])
