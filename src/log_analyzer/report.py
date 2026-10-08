"""Aggregation and rendering of parsed SSH events."""

from __future__ import annotations

import json
from collections import Counter
from collections.abc import Iterable
from dataclasses import dataclass, field
from datetime import datetime

from .parser import Event

BUCKET_FORMATS = {"hour": "%Y-%m-%d %H:00", "day": "%Y-%m-%d"}


@dataclass
class Summary:
    failed_total: int = 0
    invalid_user_total: int = 0
    accepted_total: int = 0
    first_seen: datetime | None = None
    last_seen: datetime | None = None
    top_ips: list[tuple[str, int]] = field(default_factory=list)
    top_invalid_users: list[tuple[str, int]] = field(default_factory=list)
    top_targeted_users: list[tuple[str, int]] = field(default_factory=list)
    timeline: list[tuple[str, int]] = field(default_factory=list)
    suspicious_success: list[dict[str, object]] = field(default_factory=list)


def summarize(
    events: Iterable[Event],
    top: int = 10,
    bucket: str = "hour",
    since: datetime | None = None,
    until: datetime | None = None,
) -> Summary:
    """Aggregate events. ``since``/``until`` must be timezone-aware."""
    fmt = BUCKET_FORMATS[bucket]
    ips: Counter[str] = Counter()
    invalid: Counter[str] = Counter()
    targeted: Counter[str] = Counter()
    timeline: Counter[str] = Counter()
    success: dict[tuple[str, str], datetime] = {}
    s = Summary()

    for ev in events:
        ts = ev.timestamp
        if (since and ts < since) or (until and ts > until):
            continue
        s.first_seen = ts if s.first_seen is None else min(s.first_seen, ts)
        s.last_seen = ts if s.last_seen is None else max(s.last_seen, ts)
        if ev.kind == "accepted":
            s.accepted_total += 1
            success.setdefault((ev.ip, ev.user), ts)
            continue
        if ev.kind == "invalid_user":
            s.invalid_user_total += 1
            invalid[ev.user] += 1
            continue
        s.failed_total += 1
        ips[ev.ip] += 1
        targeted[ev.user] += 1
        timeline[ts.strftime(fmt)] += 1

    s.top_ips = ips.most_common(top)
    s.top_invalid_users = invalid.most_common(top)
    s.top_targeted_users = targeted.most_common(top)
    s.timeline = sorted(timeline.items())
    # A successful login from an IP that also produced failures deserves a look.
    s.suspicious_success = [
        {"ip": ip, "user": user, "failed_attempts": ips[ip], "first_success": ts.isoformat()}
        for (ip, user), ts in sorted(success.items())
        if ips[ip] > 0
    ]
    return s


def to_dict(s: Summary) -> dict[str, object]:
    return {
        "failed_total": s.failed_total,
        "invalid_user_total": s.invalid_user_total,
        "accepted_total": s.accepted_total,
        "first_seen": s.first_seen.isoformat() if s.first_seen else None,
        "last_seen": s.last_seen.isoformat() if s.last_seen else None,
        "top_ips": [{"ip": k, "count": v} for k, v in s.top_ips],
        "top_invalid_users": [{"user": k, "count": v} for k, v in s.top_invalid_users],
        "top_targeted_users": [{"user": k, "count": v} for k, v in s.top_targeted_users],
        "timeline": [{"window": k, "failed": v} for k, v in s.timeline],
        "suspicious_success": s.suspicious_success,
    }


def render_json(s: Summary) -> str:
    return json.dumps(to_dict(s), indent=2)


def _sanitize(value: str) -> str:
    """Strip control characters so crafted usernames cannot inject terminal escapes."""
    return "".join(ch if ch.isprintable() else "?" for ch in value)


def _table(title: str, header: tuple[str, str], rows: list[tuple[str, int]]) -> list[str]:
    if not rows:
        return [f"{title}: none", ""]
    width = max(len(header[0]), *(len(_sanitize(k)) for k, _ in rows))
    out = [title, f"  {header[0]:<{width}}  {header[1]:>7}", f"  {'-' * width}  {'-' * 7}"]
    out += [f"  {_sanitize(k):<{width}}  {v:>7}" for k, v in rows]
    return [*out, ""]


def render_table(s: Summary) -> str:
    lines = [
        "SSH authentication summary",
        f"  Failed logins:     {s.failed_total}",
        f"  Invalid users:     {s.invalid_user_total}",
        f"  Accepted logins:   {s.accepted_total}",
        f"  Period:            {s.first_seen or '-'} .. {s.last_seen or '-'}",
        "",
    ]
    lines += _table("Top offending IPs", ("IP", "Failed"), s.top_ips)
    lines += _table("Top invalid users", ("User", "Count"), s.top_invalid_users)
    lines += _table("Most targeted users", ("User", "Failed"), s.top_targeted_users)
    lines += _table("Failed logins per time window", ("Window", "Failed"), s.timeline)
    if s.suspicious_success:
        lines.append("WARNING: successful logins from IPs with failed attempts")
        lines += [
            f"  {x['ip']}  user={_sanitize(str(x['user']))}  failed={x['failed_attempts']}"
            for x in s.suspicious_success
        ]
    return "\n".join(lines).rstrip() + "\n"
