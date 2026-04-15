from dns_latency_probe.utils import RateLimiter


def test_rate_limiter_requires_positive_rate() -> None:
    try:
        RateLimiter(0)
    except ValueError:
        pass
    else:
        raise AssertionError("Expected ValueError for non-positive rate")
