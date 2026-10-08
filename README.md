# log-analyzer

[![CI](https://github.com/OWNER/log-analyzer/actions/workflows/ci.yml/badge.svg)](https://github.com/OWNER/log-analyzer/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

Summarize SSH brute-force activity from `/var/log/auth.log` or `journalctl` output:
failed logins, top offending IPs, invalid user names, most targeted accounts, attack
timeline – and **successful logins from IPs that previously failed**.
Pure Python standard library, no runtime dependencies.

## Features

- Parses classic syslog (`Oct  8 10:01:02`), RFC 3339 (Debian 12+/rsyslog) and
  `journalctl -o short-iso` timestamps; supports `sshd` and `sshd-session`
- Reads files (including rotated `.gz`) or stdin
- Failed logins, invalid users, accepted logins, IPv4 and IPv6
- Top-N offending IPs / invalid users / targeted users
- Time window filter (`--since`, `--until`) and per-hour or per-day timeline
- Output as readable **table** or **JSON**
- `--fail-threshold N` → exit code `1` if any IP has ≥ N failures (for cron/monitoring)

## Installation

```bash
git clone https://github.com/OWNER/log-analyzer.git
cd log-analyzer
python3 -m venv .venv && . .venv/bin/activate
pip install .
```

## Usage

```bash
# Current and rotated auth logs (reading auth.log usually requires the adm group)
log-analyzer /var/log/auth.log /var/log/auth.log.1 /var/log/auth.log.2.gz

# systemd journal
journalctl -u ssh -o short-iso --since "24 hours ago" | log-analyzer

# JSON, top 5, specific time window, per-day timeline
log-analyzer -f json -n 5 --since 2026-10-01T00:00:00+02:00 --bucket day /var/log/auth.log

# Alert from cron when a single IP failed 50+ times
log-analyzer --fail-threshold 50 /var/log/auth.log > /dev/null || echo "brute force detected"
```

Example output:

```text
SSH authentication summary
  Failed logins:     5
  Invalid users:     2
  Accepted logins:   2
  Period:            2026-10-08 00:01:10+02:00 .. 2026-10-08 02:00:00+02:00

Top offending IPs
  IP             Failed
  ------------  -------
  203.0.113.10        3
  198.51.100.7        1

WARNING: successful logins from IPs with failed attempts
  2001:db8::25  user=deploy  failed=1
```

## Options

| Option | Default | Description |
|---|---|---|
| `files` | stdin | Log files, `.gz` supported |
| `-f, --format` | `table` | `table` or `json` |
| `-n, --top` | `10` | Entries per list (1–1000) |
| `--since` / `--until` | – | ISO 8601 time window (local time if no offset) |
| `--bucket` | `hour` | Timeline granularity: `hour` or `day` |
| `--year` | current | Year for syslog lines (which have no year) |
| `--fail-threshold N` | – | Exit `1` if any IP has ≥ N failed logins |

## Development

```bash
make venv      # create .venv with dev dependencies
make lint      # ruff check + ruff format --check
make test      # pytest with coverage (sample logs in tests/data)
make security  # bandit + pip-audit
make scan      # gitleaks secret scan (needs Docker)
```

## Security notes

- Read-only tool; it never modifies logs. Run it as a user in the `adm` group
  instead of root.
- Log content is untrusted input: IPs are validated with `ipaddress`, line length is
  capped, invalid UTF-8 is replaced, and control characters in user names are
  stripped from table output (prevents terminal escape injection).
- No `eval`, no shell, no network access. Only regular expressions without nested
  quantifiers are used (no catastrophic backtracking).
- The sample logs use documentation IP ranges (RFC 5737 / RFC 3849).

See [SECURITY.md](SECURITY.md).

## License

[MIT](LICENSE)
