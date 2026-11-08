import shlex

import pytest

from loganalyzer.fetcher import FetchError, LocalRunner, SSHRunner, fetch_lines, grep_command

SAMPLE = "samples/attack_auth.log"


def test_grep_command_quotes_path_and_pattern():
    cmd = grep_command("/var/log/auth.log; rm -rf ~", "Failed|Accepted")
    # the shell sees exactly four words after grep: -E, --, pattern, path
    assert shlex.split(cmd) == ["grep", "-E", "--", "Failed|Accepted", "/var/log/auth.log; rm -rf ~"]


def test_fetch_lines_local_returns_matching_lines():
    lines = fetch_lines(LocalRunner(), SAMPLE, "Failed|Accepted|Invalid user")
    with open(SAMPLE) as f:
        expected = [l.rstrip("\n") for l in f if any(w in l for w in ("Failed", "Accepted", "Invalid user"))]
    assert lines == expected


def test_no_match_is_not_an_error():
    assert fetch_lines(LocalRunner(), SAMPLE, "no such text anywhere") == []


def test_missing_file_raises_fetch_error():
    with pytest.raises(FetchError, match="No such file"):
        fetch_lines(LocalRunner(), "/nonexistent/auth.log")


def test_injection_in_path_is_not_executed(tmp_path):
    marker = tmp_path / "pwned"
    with pytest.raises(FetchError):
        fetch_lines(LocalRunner(), f"{SAMPLE}; touch {marker}")
    assert not marker.exists()


def test_pattern_cannot_become_an_option():
    # without "--" grep would read "-r" as an option; here it is just a pattern
    assert fetch_lines(LocalRunner(), SAMPLE, "-r") == []


def test_ssh_connection_refused_gives_fetch_error():
    # nothing listens on port 1, so connect() fails right away
    with pytest.raises(FetchError, match="Cannot connect"):
        SSHRunner("127.0.0.1", "nobody", port=1)
