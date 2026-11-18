"""Statistics for the measurement results (Section 7.2 of the requirements).

Only the standard library is used. Every function is checked in tests_c/test_stats.py
against answers worked out by hand."""
import math
import random
from dataclasses import dataclass
from fractions import Fraction
from statistics import median as _median

DEFAULT_RESAMPLES = 10_000
DEFAULT_SEED = 495  # fixed so a re-run gives the same interval (NFR-5)


def median(values: list[float]) -> float:
    if not values:
        raise ValueError("median of an empty sample")
    return float(_median(values))


def _exact(x: float | Fraction) -> Fraction:
    """The number as an exact fraction. Floats go through their decimal text, so 5.1
    becomes exactly 51/10 and not the binary value just below it."""
    return x if isinstance(x, Fraction) else Fraction(str(x))


def nearest_rank(p: float | Fraction, n: int) -> int:
    """ceil(p/100 * n), computed exactly (issue #18). In floating point, 28/100 * 25 is
    7.000000000000001 and the ceiling becomes 8 instead of 7."""
    return max(1, math.ceil(_exact(p) * n / 100))


def percentile(values: list[float], p: float | Fraction) -> float:
    """Nearest-rank percentile: the value at rank ceil(p/100 * n) in the sorted data.

    With 20 runs the 95th percentile is the 19th smallest value."""
    if not values:
        raise ValueError("percentile of an empty sample")
    if not 0 < _exact(p) <= 100:
        raise ValueError("p must be in (0, 100]")
    ordered = sorted(values)
    return float(ordered[nearest_rank(p, len(ordered)) - 1])


def bootstrap_ci_median(values: list[float], resamples: int = DEFAULT_RESAMPLES,
                        confidence: float = 0.95, seed: int = DEFAULT_SEED) -> tuple[float, float]:
    """Confidence interval of the median by bootstrap.

    1. Draw len(values) numbers from the sample WITH replacement, `resamples` times.
    2. Take the median of each draw. These medians show how much the median of this
       kind of sample moves just by chance.
    3. The interval is the middle `confidence` share of those medians: the values at
       the nearest ranks of (1-confidence)/2 and 1-(1-confidence)/2.
    """
    if not values:
        raise ValueError("bootstrap of an empty sample")
    rng = random.Random(seed)
    n = len(values)
    medians = [_median(rng.choices(values, k=n)) for _ in range(resamples)]
    # Exact arithmetic (issue #18): in floating point (1 - 0.95) / 2 * 100 is
    # 2.500000000000002, which moved the lower bound from rank 250 to 251 of 10,000.
    alpha = (1 - _exact(confidence)) / 2 * 100
    return percentile(medians, alpha), percentile(medians, 100 - alpha)


def intervals_overlap(a: tuple[float, float], b: tuple[float, float]) -> bool:
    return a[0] <= b[1] and b[0] <= a[1]


@dataclass(frozen=True)
class Summary:
    n: int
    median: float
    p95: float
    ci_low: float
    ci_high: float


def summarize(values: list[float], resamples: int = DEFAULT_RESAMPLES, seed: int = DEFAULT_SEED) -> Summary:
    low, high = bootstrap_ci_median(values, resamples=resamples, seed=seed)
    return Summary(len(values), median(values), percentile(values, 95), low, high)


def differ(a: list[float], b: list[float], resamples: int = DEFAULT_RESAMPLES, seed: int = DEFAULT_SEED) -> bool:
    """Two methods are reported as different only if their intervals do not overlap."""
    return not intervals_overlap(
        bootstrap_ci_median(a, resamples, seed=seed), bootstrap_ci_median(b, resamples, seed=seed)
    )
