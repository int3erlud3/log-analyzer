from datetime import datetime, timezone

import pytest

from log_analyzer.parser import parse_line, parse_lines

UTC = timezone.utc


def test_failed_password_syslog():
    ev = parse_line(
        "Oct  8 00:01:20 web01 sshd[2002]: Failed password for root from 203.0.113.10 port 51002 ssh2",
        year=2026,
        tz=UTC,
    )
    assert ev is not None
    assert (ev.kind, ev.user, ev.ip, ev.host) == ("failed", "root", "203.0.113.10", "web01")
    assert ev.timestamp == datetime(2026, 10, 8, 0, 1, 20, tzinfo=UTC)
    assert not ev.invalid_user


def test_failed_password_invalid_user():
    ev = parse_line(
        "Oct  8 00:01:12 web01 sshd[1]: Failed password for invalid user admin from 203.0.113.10 port 5 ssh2",
        year=2026,
        tz=UTC,
    )
    assert ev is not None
    assert ev.user == "admin"
    assert ev.invalid_user


def test_invalid_user_line():
    ev = parse_line("Oct  8 00:15:00 h sshd[1]: Invalid user oracle from 198.51.100.7 port 4", 2026, UTC)
    assert ev is not None
    assert (ev.kind, ev.user) == ("invalid_user", "oracle")


def test_ipv6_and_accepted():
    ev = parse_line("Oct  8 01:05:00 h sshd[1]: Accepted publickey for deploy from 2001:db8::25 port 6 ssh2")
    assert ev is not None
    assert ev.kind == "accepted"
    assert ev.ip == "2001:db8::25"


@pytest.mark.parametrize(
    ("line", "expected"),
    [
        (
            "2026-10-08T10:00:09+0200 web02 sshd[1]: Failed password for root from 203.0.113.99 port 4 ssh2",
            datetime(2026, 10, 8, 8, 0, 9, tzinfo=UTC),
        ),
        (
            "2026-10-08T11:30:00.123456789+02:00 h sshd-session[1]: "
            "Failed password for root from 1.2.3.4 port 4",
            datetime(2026, 10, 8, 9, 30, 0, 123456, tzinfo=UTC),
        ),
        (
            "2026-10-08T08:45:00Z h sshd[1]: Failed password for root from 1.2.3.4 port 4 ssh2",
            datetime(2026, 10, 8, 8, 45, tzinfo=UTC),
        ),
    ],
)
def test_iso_timestamps(line, expected):
    ev = parse_line(line)
    assert ev is not None
    assert ev.timestamp == expected


@pytest.mark.parametrize(
    "line",
    [
        "",
        "garbage",
        "Oct  8 02:10:00 web01 sshd[2008]: Failed password for root from not-an-ip port 1 ssh2",
        "Oct  8 02:11:00 web01 sshd[2009]: Connection closed by authenticating user root 1.2.3.4 port 1",
        "Oct  8 02:11:00 web01 sudo[2009]: Failed password for root from 1.2.3.4 port 1 ssh2",
        "Feb 30 02:11:00 web01 sshd[1]: Failed password for root from 1.2.3.4 port 1 ssh2",
    ],
)
def test_irrelevant_or_malformed_lines_are_ignored(line):
    assert parse_line(line, year=2026, tz=UTC) is None


def test_parse_sample_file(data_dir):
    lines = (data_dir / "auth.log").read_text().splitlines()
    events = list(parse_lines(lines, year=2026, tz=UTC))
    kinds = [e.kind for e in events]
    assert kinds.count("failed") == 5
    assert kinds.count("invalid_user") == 2
    assert kinds.count("accepted") == 2
