import gzip
import io
import json
import shutil

import pytest

from log_analyzer.cli import main
from log_analyzer.parser import parse_lines
from log_analyzer.report import render_table, summarize


def run_json(capsys, *argv):
    rc = main(["--format", "json", *argv])
    return rc, json.loads(capsys.readouterr().out)


def test_summary_counts(data_dir, capsys):
    rc, out = run_json(capsys, "--year", "2026", str(data_dir / "auth.log"))
    assert rc == 0
    assert out["failed_total"] == 5
    assert out["invalid_user_total"] == 2
    assert out["accepted_total"] == 2
    assert out["top_ips"][0] == {"ip": "203.0.113.10", "count": 3}
    assert {u["user"] for u in out["top_invalid_users"]} == {"admin", "oracle"}
    assert out["top_targeted_users"][0] == {"user": "root", "count": 2}


def test_suspicious_success_detected(data_dir, capsys):
    _, out = run_json(capsys, "--year", "2026", str(data_dir / "auth.log"))
    assert len(out["suspicious_success"]) == 1
    hit = out["suspicious_success"][0]
    assert (hit["ip"], hit["user"], hit["failed_attempts"]) == ("2001:db8::25", "deploy", 1)


def test_time_window_and_bucket(data_dir, capsys):
    rc, out = run_json(
        capsys,
        "--since",
        "2026-10-08T10:00:05+02:00",
        "--until",
        "2026-10-08T12:00:00+02:00",
        "--bucket",
        "hour",
        str(data_dir / "journal.log"),
    )
    assert rc == 0
    assert out["failed_total"] == 2
    assert [w["window"] for w in out["timeline"]] == ["2026-10-08 10:00", "2026-10-08 11:00"]


def test_multiple_files_and_gzip(data_dir, tmp_path, capsys):
    gz = tmp_path / "auth.log.1.gz"
    with (data_dir / "auth.log").open("rb") as src, gzip.open(gz, "wb") as dst:
        shutil.copyfileobj(src, dst)
    _, out = run_json(capsys, "--year", "2026", str(gz), str(data_dir / "journal.log"))
    assert out["failed_total"] == 8


def test_stdin(data_dir, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO((data_dir / "journal.log").read_text()))
    _, out = run_json(capsys)
    assert out["failed_total"] == 3


def test_table_output(data_dir, capsys):
    assert main(["--year", "2026", "--top", "1", str(data_dir / "auth.log")]) == 0
    out = capsys.readouterr().out
    assert "Top offending IPs" in out
    assert "203.0.113.10" in out
    assert "198.51.100.7" not in out.split("Top invalid users")[0]  # --top 1


def test_fail_threshold_exit_code(data_dir, capsys):
    assert main(["--fail-threshold", "3", str(data_dir / "auth.log")]) == 1
    assert main(["--fail-threshold", "4", str(data_dir / "auth.log")]) == 0


def test_missing_file_returns_2(tmp_path, capsys):
    assert main([str(tmp_path / "nope.log")]) == 2
    assert "error" in capsys.readouterr().err


@pytest.mark.parametrize("argv", [["--top", "0"], ["--top", "abc"], ["--since", "yesterday"], ["-f", "xml"]])
def test_invalid_arguments(argv):
    with pytest.raises(SystemExit) as exc:
        main(argv)
    assert exc.value.code == 2


def test_control_characters_are_sanitized():
    line = "2026-10-08T10:00:01+0200 h sshd[1]: Invalid user \x1b[31mevil from 203.0.113.1 port 1"
    out = render_table(summarize(parse_lines([line])))
    assert "\x1b" not in out
    assert "?[31mevil" in out


def test_empty_input(capsys, monkeypatch):
    monkeypatch.setattr("sys.stdin", io.StringIO(""))
    assert main([]) == 0
    assert "Failed logins:     0" in capsys.readouterr().out
