"""Command line interface for log-analyzer."""

from __future__ import annotations

import argparse
import gzip
import sys
from collections.abc import Iterator, Sequence
from datetime import datetime
from pathlib import Path

from . import __version__
from .parser import parse_lines
from .report import BUCKET_FORMATS, render_json, render_table, summarize

MAX_LINE = 64 * 1024  # guard against pathological input lines


def _aware(value: str) -> datetime:
    try:
        ts = datetime.fromisoformat(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(f"invalid ISO 8601 timestamp: {value!r}") from exc
    return ts if ts.tzinfo else ts.astimezone()


def _positive(value: str) -> int:
    if not value.isdigit() or not 1 <= int(value) <= 1000:
        raise argparse.ArgumentTypeError("must be an integer between 1 and 1000")
    return int(value)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="log-analyzer",
        description="Summarize failed SSH logins from auth.log or journalctl output.",
    )
    p.add_argument("files", nargs="*", type=Path, help="log files (.gz supported); default: stdin")
    p.add_argument("-f", "--format", choices=("table", "json"), default="table")
    p.add_argument("-n", "--top", type=_positive, default=10, help="entries per list (default 10)")
    p.add_argument("--since", type=_aware, help="ignore events before this ISO 8601 time")
    p.add_argument("--until", type=_aware, help="ignore events after this ISO 8601 time")
    p.add_argument("--bucket", choices=sorted(BUCKET_FORMATS), default="hour")
    p.add_argument("--year", type=int, help="year for syslog lines without a year (default: current)")
    p.add_argument(
        "--fail-threshold",
        type=int,
        metavar="N",
        help="exit with status 1 if any single IP has at least N failed logins",
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def _read_lines(paths: Sequence[Path]) -> Iterator[str]:
    if not paths:
        for line in sys.stdin:
            yield line[:MAX_LINE]
        return
    for path in paths:
        opener = gzip.open if path.suffix == ".gz" else open
        with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                yield line[:MAX_LINE]


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        events = parse_lines(_read_lines(args.files), year=args.year)
        summary = summarize(events, top=args.top, bucket=args.bucket, since=args.since, until=args.until)
    except OSError as exc:
        print(f"log-analyzer: error: {exc}", file=sys.stderr)
        return 2
    print(render_json(summary) if args.format == "json" else render_table(summary), end="")
    if args.format == "json":
        print()
    if args.fail_threshold and summary.top_ips and summary.top_ips[0][1] >= args.fail_threshold:
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
