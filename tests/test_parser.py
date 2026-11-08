from collections import Counter
from datetime import datetime
from pathlib import Path

import pytest

from loganalyzer.parser import parse_line, parse_lines

# the day after the samples were recorded - otherwise classic "Oct 28" lines fall into last year
NOW = datetime(2026, 10, 29, 12, 0)
SAMPLES = Path(__file__).parent.parent / "samples"


@pytest.mark.parametrize("line, kind, user, ip, port", [
    ("Oct 18 03:00:01 srv sshd[812]: Failed password for root from 203.0.113.5 port 52114 ssh2",
     "failed", "root", "203.0.113.5", 52114),
    ("Oct  8 03:00:02 srv sshd[813]: Invalid user bob from 198.51.100.7 port 40022",
     "invalid_user", "bob", "198.51.100.7", 40022),
    ("2026-10-18T09:15:00.123456+02:00 srv sshd-session[900]: Accepted publickey for ana from ::1 port 50000 ssh2",
     "accepted", "ana", "::1", 50000),
    ("2026-10-28T03:03:17.884196+01:00 ian-Vostro-3520 sshd[3250]: Failed password for invalid user oracle from 2001:db8::1 port 50000 ssh2",
     "failed", "oracle", "2001:db8::1", 50000),
    ("Oct 18 03:00:03 srv sshd[814]: Failed password for invalid user  from 203.0.113.9 port 40100 ssh2",
     "failed", "", "203.0.113.9", 40100),
])
def test_parses_known_lines(line, kind, user, ip, port):
    e = parse_line(line, NOW)
    assert (e.kind, e.user, e.ip, e.port) == (kind, user, ip, port)


@pytest.mark.parametrize("line", [
    "Oct 18 03:00:00 srv CRON[700]: pam_unix(cron:session): session opened for user root",
    "2026-10-28T03:02:00.661089+01:00 ian-Vostro-3520 sshd[3216]: pam_unix(sshd:session): session opened for user root(uid=0) by root(uid=0)",
    "2026-10-28T02:58:00.012733+01:00 ian-Vostro-3520 sshd[3140]: Connection closed by invalid user test 198.51.100.7 port 40110 [preauth]",
    "",
])
def test_irrelevant_line_is_ignored(line):
    assert parse_line(line, NOW) is None


def test_repeated_message_sets_count():
    line = ("Oct 18 03:00:09 srv sshd[812]: message repeated 4 times: "
            "[ Failed password for root from 203.0.113.5 port 52114 ssh2]")
    e = parse_line(line, NOW)
    assert e.kind == "failed" and e.count == 4


def test_december_line_read_in_january_is_last_year():
    e = parse_line("Dec 31 23:59:00 srv sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
                   datetime(2027, 1, 1, 0, 5))
    assert e.timestamp == datetime(2026, 12, 31, 23, 59)


def test_iso_timestamp_drops_timezone():
    e = parse_line("2026-10-28T22:46:27.469775+01:00 h sshd[5]: Accepted password for ian from 127.0.0.1 port 1 ssh2", NOW)
    assert e.timestamp == datetime(2026, 10, 28, 22, 46, 27, 469775)


def test_sample_log_has_all_event_types():
    with open(SAMPLES / "sample_auth.log") as f:
        kinds = Counter(e.kind for e in parse_lines(f, NOW))
    assert kinds["failed"] > 0 and kinds["accepted"] > 0 and kinds["invalid_user"] > 0


def test_attack_log():
    with open(SAMPLES / "attack_auth.log") as f:
        events = parse_lines(f, NOW)
    attacker_failed = sum(e.count for e in events if e.ip == "203.0.113.5" and e.kind == "failed")
    assert attacker_failed == 15
    assert any(e.ip == "203.0.113.5" and e.kind == "accepted" and e.user == "root" for e in events)
    assert sum(e.count for e in events if e.ip == "198.51.100.7" and e.kind == "failed") == 4
    assert events == sorted(events, key=lambda e: e.timestamp)
    # classic lines at the end of the file must stay at the end, in the same year
    assert events[0].timestamp == datetime(2026, 10, 28, 2, 55, 10, 104512)
    assert (events[-1].timestamp, events[-1].kind) == (datetime(2026, 10, 28, 3, 6, 20), "accepted")
