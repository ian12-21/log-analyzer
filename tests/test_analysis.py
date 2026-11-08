from datetime import datetime
from pathlib import Path

from loganalyzer.analysis import Stats, summarize
from loganalyzer.parser import Event, parse_lines

# the day after the samples were recorded - otherwise classic "Oct 28" lines fall into last year
NOW = datetime(2026, 10, 29, 12, 0)
SAMPLES = Path(__file__).parent.parent / "samples"


def ev(kind, user, ip, hour, minute=0, count=1):
    return Event(timestamp=datetime(2026, 10, 18, hour, minute), kind=kind, user=user,
                 ip=ip, port=22, host="srv", count=count)


EVENTS = [
    ev("failed", "root", "1.1.1.1", 1),
    ev("failed", "root", "1.1.1.1", 1, 5, count=3),   # message repeated 3 times
    ev("invalid_user", "admin", "2.2.2.2", 1, 10),
    ev("failed", "admin", "2.2.2.2", 1, 10),
    ev("accepted", "ian", "3.3.3.3", 2),
    ev("failed", "ian", "3.3.3.3", 4, 30),
]


def test_totals_use_repeated_count():
    s = summarize(EVENTS)
    assert (s.failed, s.accepted) == (6, 1)


def test_invalid_user_is_not_a_failed_attempt():
    s = summarize([ev("invalid_user", "admin", "2.2.2.2", 1)])
    assert s.failed == 0
    assert s.top_invalid_users() == [("admin", 1)]


def test_top_ips_and_users():
    s = summarize(EVENTS)
    assert s.top_ips() == [("1.1.1.1", 4), ("2.2.2.2", 1), ("3.3.3.3", 1)]
    assert s.top_users(1) == [("root", 4)]


def test_accepted_does_not_count_towards_top_ips():
    s = summarize([ev("accepted", "ian", "3.3.3.3", 2)])
    assert s.top_ips() == [] and s.top_users() == []


def test_hourly_series_fills_missing_hours_with_zero():
    s = summarize(EVENTS)
    assert s.hourly_series() == [
        (datetime(2026, 10, 18, 1), 5),
        (datetime(2026, 10, 18, 2), 0),
        (datetime(2026, 10, 18, 3), 0),
        (datetime(2026, 10, 18, 4), 1),
    ]


def test_add_one_by_one_matches_summarize():
    s = Stats()
    for e in EVENTS:
        s.add(e)
    assert (s.failed, s.accepted, s.top_ips()) == (6, 1, summarize(EVENTS).top_ips())


def test_empty_stats():
    s = Stats()
    assert (s.failed, s.accepted) == (0, 0)
    assert s.top_ips() == [] and s.hourly_series() == []


# Expected numbers checked with grep -c ("message repeated 2 times" lines count twice)
def test_sample_log_totals():
    with open(SAMPLES / "sample_auth.log") as f:
        s = summarize(parse_lines(f, NOW))
    assert (s.failed, s.accepted) == (22, 7)


def test_attack_log():
    with open(SAMPLES / "attack_auth.log") as f:
        s = summarize(parse_lines(f, NOW))
    assert (s.failed, s.accepted) == (21, 4)
    assert s.top_ips(1) == [("203.0.113.5", 15)]
    assert s.top_users(2) == [("root", 13), ("test", 4)]
    assert sorted(s.top_invalid_users()) == [("guest", 1), ("oracle", 1), ("test", 1)]
    assert s.hourly_series() == [(datetime(2026, 10, 28, 2), 4), (datetime(2026, 10, 28, 3), 17)]
