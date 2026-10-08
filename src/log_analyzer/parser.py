"""Parsing of sshd log lines into structured events.

Supported timestamp formats:

* classic syslog:            ``Oct  8 10:01:02 host sshd[123]: ...``
* RFC 3339 (rsyslog/Debian): ``2026-10-08T10:01:02.123456+02:00 host sshd[123]: ...``
* ``journalctl -o short-iso``: ``2026-10-08T10:01:02+0200 host sshd[123]: ...``
"""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timezone

SYSLOG_RE = re.compile(
    r"^(?P<ts>[A-Z][a-z]{2} [ \d]\d \d{2}:\d{2}:\d{2}) (?P<host>\S+) sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)
ISO_RE = re.compile(
    r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})) "
    r"(?P<host>\S+) sshd(?:-session)?\[\d+\]: (?P<msg>.*)$"
)

_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
_USER = r"(?P<user>\S{1,64})"
MESSAGE_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("failed", re.compile(rf"^Failed \S+ for invalid user {_USER} from {_IP} port \d+")),
    ("failed", re.compile(rf"^Failed \S+ for {_USER} from {_IP} port \d+")),
    ("invalid_user", re.compile(rf"^Invalid user {_USER} from {_IP}(?: port \d+)?")),
    ("accepted", re.compile(rf"^Accepted \S+ for {_USER} from {_IP} port \d+")),
]


@dataclass(frozen=True)
class Event:
    """A single SSH authentication event."""

    timestamp: datetime
    kind: str  # failed | invalid_user | accepted
    user: str
    ip: str
    host: str
    invalid_user: bool = False


_TZ_FIX = re.compile(r"(?:Z|([+-]\d{2}):?(\d{2}))$")
_FRACTION = re.compile(r"\.(\d+)")


def _normalize_iso(raw: str) -> str:
    """Make RFC 3339 / journald timestamps parseable by Python 3.10's fromisoformat."""
    raw = _TZ_FIX.sub(lambda m: f"{m.group(1)}:{m.group(2)}" if m.group(1) else "+00:00", raw)
    return _FRACTION.sub(lambda m: "." + m.group(1)[:6].ljust(6, "0"), raw)


def _parse_timestamp(raw: str, year: int, tz: timezone | None) -> datetime | None:
    try:
        if raw[0].isdigit():
            ts = datetime.fromisoformat(_normalize_iso(raw))
        else:
            ts = datetime.strptime(f"{year} {raw}", "%Y %b %d %H:%M:%S")
            ts = ts.replace(tzinfo=tz) if tz else ts.astimezone()
    except ValueError:
        return None
    return ts


def _valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def parse_line(line: str, year: int | None = None, tz: timezone | None = None) -> Event | None:
    """Parse one log line. Returns ``None`` for lines that are not SSH auth events."""
    line = line.rstrip("\n")
    match = SYSLOG_RE.match(line) or ISO_RE.match(line)
    if not match:
        return None
    msg = match.group("msg")
    for kind, pattern in MESSAGE_PATTERNS:
        m = pattern.match(msg)
        if not m or not _valid_ip(m.group("ip")):
            continue
        ts = _parse_timestamp(match.group("ts"), year or datetime.now().year, tz)
        if ts is None:
            return None
        return Event(
            timestamp=ts,
            kind=kind,
            user=m.group("user"),
            ip=m.group("ip"),
            host=match.group("host"),
            invalid_user=kind == "invalid_user" or "invalid user" in msg[:40],
        )
    return None


def parse_lines(lines: Iterable[str], year: int | None = None, tz: timezone | None = None) -> Iterator[Event]:
    """Yield events from an iterable of log lines, skipping unrelated lines."""
    for line in lines:
        event = parse_line(line, year=year, tz=tz)
        if event is not None:
            yield event
