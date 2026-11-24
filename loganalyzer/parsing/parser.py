import hashlib
import re
from datetime import datetime, timedelta, timezone

from loganalyzer.domain.models import LogEntry

LINE_RE = re.compile(
    r"^(?P<ip>\S+) \S+ \S+ "
    r"\[(?P<time>[^\]]+)\] "
    r'"(?P<request>(?:[^"\\]|\\.)*)" '
    r"(?P<status>\d{3}) (?P<bytes>\d+|-) "
    r'"(?P<referer>(?:[^"\\]|\\.)*)" '
    r'"(?P<ua>(?:[^"\\]|\\.)*)"$'
)

MONTHS = {
    "Jan": 1, "Feb": 2, "Mar": 3, "Apr": 4, "May": 5, "Jun": 6,
    "Jul": 7, "Aug": 8, "Sep": 9, "Oct": 10, "Nov": 11, "Dec": 12,
}


class ParseError(ValueError):
    """Рядок не вдалося розібрати."""


def parse_time(text: str) -> datetime:
    """'23/Nov/2026:05:09:37 +0200' -> datetime з часовим поясом."""
    try:
        date_part, tz_part = text.split(" ")
        day, month, rest = date_part.split("/")
        year, hour, minute, second = rest.split(":")
        sign = -1 if tz_part[0] == "-" else 1
        offset = timedelta(hours=int(tz_part[1:3]), minutes=int(tz_part[3:5]))
        return datetime(
            int(year), MONTHS[month], int(day),
            int(hour), int(minute), int(second),
            tzinfo=timezone(sign * offset),
        )
    except (ValueError, KeyError, IndexError) as exc:
        raise ParseError(f"Некоректний час: {text!r}") from exc


def parse_line(line: str) -> LogEntry:
    """Розбирає один рядок. Якщо не вийшло, кидає ParseError."""
    line = line.rstrip("\r\n")
    match = LINE_RE.match(line)
    if match is None:
        raise ParseError("Рядок не відповідає формату Combined")

    parts = match["request"].split(" ")
    if len(parts) == 3:
        method, path, protocol = parts
    elif len(parts) == 2:
        method, path = parts
        protocol = ""
    else:
        method, path, protocol = "-", match["request"], ""

    try:
        return LogEntry(
            ip=match["ip"],
            timestamp=parse_time(match["time"]),
            method=method,
            path=path,
            protocol=protocol,
            status=int(match["status"]),
            bytes_sent=0 if match["bytes"] == "-" else int(match["bytes"]),
            referer=match["referer"],
            user_agent=match["ua"],
            line_hash=hashlib.sha256(line.encode("utf-8", "replace")).hexdigest(),
        )
    except ValueError as exc:
        raise ParseError(str(exc)) from exc