import re
from dataclasses import dataclass
from datetime import datetime, timedelta


@dataclass(frozen=True)
class Event:
    timestamp: datetime
    kind: str          # "failed" | "accepted" | "invalid_user"
    user: str
    ip: str
    port: int | None
    host: str
    count: int = 1     # za "message repeated N times"


# Zaglavlje: klasični ("Oct 28 03:06:02") ili ISO 8601 timestamp, host, sshd/sshd-session[pid]
HEADER_RE = re.compile(
    r"^(?P<ts>\w{3} [ \d]\d \d{2}:\d{2}:\d{2}|\d{4}-\d{2}-\d{2}T\S+)\s+"
    r"(?P<host>\S+)\s+sshd(?:-session)?\[\d+\]:\s+(?P<msg>.*)$"
)
# \S+ za IP da prođe i IPv6, \S* za korisnika jer ime može biti prazno
FAILED_RE = re.compile(r"^Failed \S+ for (?:invalid user )?(?P<user>\S*) from (?P<ip>\S+) port (?P<port>\d+)")
ACCEPTED_RE = re.compile(r"^Accepted \S+ for (?P<user>\S+) from (?P<ip>\S+) port (?P<port>\d+)")
INVALID_RE = re.compile(r"^Invalid user (?P<user>\S*) from (?P<ip>\S+)(?: port (?P<port>\d+))?")
REPEATED_RE = re.compile(r"^message repeated (?P<n>\d+) times: \[ ?(?P<inner>.*?) ?\]$")

PATTERNS = [("failed", FAILED_RE), ("accepted", ACCEPTED_RE), ("invalid_user", INVALID_RE)]


def parse_timestamp(raw: str, now: datetime) -> datetime:
    if raw[0].isdigit():
        return datetime.fromisoformat(raw).replace(tzinfo=None)
    # klasični format nema godinu: uzmi tekuću, a ako ispadne u budućnosti, to je prošla godina
    ts = datetime.strptime(f"{now.year} {raw}", "%Y %b %d %H:%M:%S")
    if ts > now + timedelta(days=1):
        ts = ts.replace(year=now.year - 1)
    return ts


def parse_line(line: str, now: datetime | None = None) -> Event | None:
    m = HEADER_RE.match(line.rstrip())
    if not m:
        return None
    msg, count = m["msg"], 1
    if rep := REPEATED_RE.match(msg):
        msg, count = rep["inner"], int(rep["n"])
    for kind, regex in PATTERNS:
        if mm := regex.match(msg):
            port = mm["port"]
            return Event(timestamp=parse_timestamp(m["ts"], now or datetime.now()),
                         kind=kind, user=mm["user"], ip=mm["ip"],
                         port=int(port) if port else None, host=m["host"], count=count)
    return None


def parse_lines(lines, now: datetime | None = None) -> list[Event]:
    events = [e for line in lines if (e := parse_line(line, now))]
    events.sort(key=lambda e: e.timestamp)
    return events
