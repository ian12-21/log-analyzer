from collections import Counter
from datetime import datetime, timedelta

from loganalyzer.parser import Event


class Stats:
    """Statistics filled one event at a time - the same code for a whole log and for the stream."""

    def __init__(self) -> None:
        self.failed = 0
        self.accepted = 0
        self.ips: Counter[str] = Counter()
        self.users: Counter[str] = Counter()
        self.invalid_users: Counter[str] = Counter()
        self.per_hour: Counter[datetime] = Counter()

    def add(self, e: Event) -> None:
        if e.kind == "accepted":
            self.accepted += e.count
        elif e.kind == "failed":
            self.failed += e.count
            self.ips[e.ip] += e.count
            self.users[e.user] += e.count
            hour = e.timestamp.replace(minute=0, second=0, microsecond=0)
            self.per_hour[hour] += e.count
        elif e.kind == "invalid_user":
            # the same attempt is already counted as "failed", here only names that do not exist
            self.invalid_users[e.user] += e.count

    def top_ips(self, n: int = 10) -> list[tuple[str, int]]:
        return self.ips.most_common(n)

    def top_users(self, n: int = 10) -> list[tuple[str, int]]:
        return self.users.most_common(n)

    def top_invalid_users(self, n: int = 10) -> list[tuple[str, int]]:
        return self.invalid_users.most_common(n)

    def hourly_series(self) -> list[tuple[datetime, int]]:
        """Every hour from the first to the last, including zeros - a chart without gaps."""
        if not self.per_hour:
            return []
        h, end = min(self.per_hour), max(self.per_hour)
        series = []
        while h <= end:
            series.append((h, self.per_hour[h]))
            h += timedelta(hours=1)
        return series


def summarize(events) -> Stats:
    stats = Stats()
    for e in events:
        stats.add(e)
    return stats
