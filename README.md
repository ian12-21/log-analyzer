# log-analyzer

A tool for analyzing SSH logins on a remote Linux system. It fetches
`/var/log/auth.log` over SSH (filtered on the server), extracts failed and
successful logins, and shows statistics and alerts about suspicious activity
(brute-force attacks, a successful login after a run of failures) in the
terminal or in a Textual TUI.

## Status

The project is a work in progress. Done so far:

- [x] environment setup and project structure
- [x] sample logs (`samples/`)
- [x] parser (`loganalyzer/parser.py`) with tests
- [x] analysis and statistics (`loganalyzer/analysis.py`) with tests
- [ ] fetching over SSH and rotated (`.gz`) logs
- [ ] CLI and summary output (KT1)
- [ ] delta reading and real-time streaming
- [ ] suspicious activity detection
- [ ] Textual TUI, date filtering and CSV export (KT2)

The development log is in `progress/`.

## Requirements

- Python 3.10 or newer (developed on 3.12)
- Target system: Linux running `sshd` and `rsyslog` (which writes `/var/log/auth.log`)

## Installation

```bash
git clone https://github.com/ian12-21/log-analyzer.git
cd log-analyzer
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

## Server setup

The tool reads `auth.log` without `sudo`, so the user on the server must be in
the `adm` group:

```bash
sudo usermod -aG adm $USER   # then log out and back in
ls -l /var/log/auth.log      # owner syslog, group adm
```

Logging in with an SSH key is recommended. The host must be in
`~/.ssh/known_hosts` (connecting once manually with `ssh` is enough). Check:

```bash
ssh localhost 'tail -n 3 /var/log/auth.log'
```

The command must print log lines without asking for a password.

## Usage

The parser can already be used from Python:

```python
from loganalyzer.parser import parse_lines

with open("samples/attack_auth.log") as f:
    events = parse_lines(f)

for e in events[:3]:
    print(e.timestamp, e.kind, e.user, e.ip)
```

Statistics over the parsed events:

```python
from loganalyzer.analysis import summarize

stats = summarize(events)
print(stats.failed, stats.accepted)   # weighted by `message repeated` counts
print(stats.top_ips(5))               # failed attempts per IP
print(stats.top_invalid_users(5))     # non-existent user names
print(stats.hourly_series())          # (hour, failed) including zero hours
```

Planned command-line interface (not implemented yet):

```bash
python -m loganalyzer summary --host localhost --rotated
python -m loganalyzer stream --host localhost
python -m loganalyzer tui --host localhost
python -m loganalyzer export --since 2026-10-18 events.csv
```

## Supported log formats

The parser handles both timestamp formats and both process names:

| Variant | Example line prefix |
|---|---|
| Classic syslog (Ubuntu 22.04 and older) | `Oct 18 14:02:11 laptop sshd[2211]:` |
| ISO 8601 (Ubuntu 24.04+) | `2026-10-18T14:02:11.123456+02:00 laptop sshd[2211]:` |
| OpenSSH 9.8+ | `... laptop sshd-session[2211]:` |

Recognized messages:

| Event type (`kind`) | Message |
|---|---|
| `failed` | `Failed password for [invalid user] <user> from <ip> port <port>` |
| `accepted` | `Accepted <method> for <user> from <ip> port <port>` |
| `invalid_user` | `Invalid user <user> from <ip> [port <port>]` |

A `message repeated N times: [ ... ]` line becomes one event with `count = N`.
Other lines (`pam_unix`, `Connection closed`, etc.) are ignored.

Only `failed` counts as a failed attempt. An attempt on a non-existent user
produces two log lines (`Invalid user` and `Failed password for invalid user`),
so `invalid_user` is used only for statistics on non-existent user names.

## Architecture

Data flows in one direction: fetcher → parser → analysis and detection → output.
The parser, analysis and detection don't depend on the network or the screen,
so they are tested without SSH.

| Module | Role |
|---|---|
| `fetcher.py` | runs commands over SSH (or locally) and returns log lines |
| `parser.py` | turns a log line into an `Event` or `None` |
| `analysis.py` | statistics: login counts, top IP addresses and users, attempts per hour |
| `detection.py` | sliding time window for brute-force and success-after-failures alerts |
| `state.py` | stores the read offset and inode for delta reading |
| `export.py` | exports events and alerts to CSV |
| `cli.py` | command-line arguments and summary output |
| `tui.py` | Textual interface with summary, charts and a live view |

Other directories:

- `samples/sample_auth.log` – 70 real `sshd` lines from the development machine
- `samples/attack_auth.log` – a hand-written sample with a brute-force attack, an
  IPv6 address and a `message repeated` line, for detection tests
- `tests/` – pytest tests
- `scripts/` – helper scripts

## Tests

```bash
pytest
```

## Limitations

- Only Linux and `auth.log` (rsyslog) are supported. Systems that use only
  journald are not.
- The classic timestamp format has no year. A date that would fall in the future
  is assigned to the previous year, so logs older than one year won't get the
  correct year.
- The timezone from the ISO format is dropped; times are the server's local time.
