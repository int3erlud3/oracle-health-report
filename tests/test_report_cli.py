import base64
import hashlib
import json
import re
import stat

import pytest

from oracle_health_report import cli
from oracle_health_report.checks import Section
from oracle_health_report.report import CSS, Report, render_html, render_text


def test_html_escapes_untrusted_values(fake_db, data):
    evil = "<script>alert(1)</script>"
    data["alert_log"] = [{"originating_timestamp": None, "message_text": f"ORA-12345 {evil}"}]
    data["tablespaces"][0]["tablespace_name"] = '"><img src=x onerror=alert(1)>'
    from oracle_health_report.checks import Thresholds, run_checks

    html = render_html(Report(run_checks(fake_db.fetch, Thresholds()), target="u@db"))
    assert evil not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<img" not in html
    assert "<script" not in html


def test_html_has_strict_csp_matching_inline_style():
    html = render_html(Report([Section("x", "X")], target="u@db"))
    digest = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    csp = re.search(r'Content-Security-Policy" content="([^"]+)"', html).group(1)
    assert "default-src 'none'" in csp
    assert f"style-src 'sha256-{digest}'" in csp
    assert f"<style>{CSS}</style>" in html


def test_text_and_exit_code():
    s = Section("t", "Tablespaces")
    s.add("WARNING", "USERS is 90% full")
    r = Report([s, Section("i", "Instance")], target="u@db")
    assert r.status == "WARNING" and r.exit_code == 1
    text = render_text(r)
    assert "[WARNING ] Tablespaces" in text and text.endswith("OVERALL: WARNING")


def test_cli_json(patched_connect, capsys):
    rc = cli.main(["--format", "json", "--no-banner"])
    out = json.loads(capsys.readouterr().out)
    assert rc == 0 and out["status"] == "OK"
    assert out["target"] == "health_monitor@db1:1521/FREEPDB1"
    assert out["sections"][0]["tables"][0]["rows"][0]["startup_time"] == "2026-10-01T06:00:00"
    assert "not-a-real-password" not in json.dumps(out)
    assert patched_connect.closed


def test_cli_security_only_and_exit_code(patched_connect, data, capsys):
    data["public_sys_privs"] = [{"privilege": "CREATE SESSION"}]
    rc = cli.main(["--security-only", "--no-banner"])
    out = capsys.readouterr().out
    assert rc == 2
    assert "Tablespace" not in out and "PUBLIC has CREATE SESSION" in out


def test_cli_writes_private_html_file(patched_connect, tmp_path, capsys):
    target = tmp_path / "report.html"
    rc = cli.main(["--format", "html", "-o", str(target), "--timeout", "5"])
    assert rc == 0
    assert stat.S_IMODE(target.stat().st_mode) == 0o600
    assert target.read_text().startswith("<!DOCTYPE html>")
    assert patched_connect.calls[0][1] == 5000


def test_cli_refuses_symlink_output(patched_connect, tmp_path):
    (tmp_path / "real").write_text("")
    (tmp_path / "link").symlink_to(tmp_path / "real")
    with pytest.raises(OSError):
        cli.main(["-o", str(tmp_path / "link"), "--no-banner"])


def test_cli_config_error_is_unknown(monkeypatch, capsys):
    monkeypatch.delenv("ORACLE_DSN", raising=False)
    assert cli.main(["--no-banner"]) == 3
    assert "ORACLE_DSN" in capsys.readouterr().err


def test_cli_connect_error_is_unknown(monkeypatch, ora_env, capsys):
    from oracle_health_report import db

    def boom(cfg, call_timeout_ms):
        raise RuntimeError("DPY-6005: cannot connect to database\nstack")

    monkeypatch.setattr(db, "connect", boom)
    assert cli.main(["--no-banner"]) == 3
    err = capsys.readouterr().err
    assert "DPY-6005" in err and "stack" not in err and "not-a-real-password" not in err


def test_cli_has_no_credential_options():
    opts = {o for a in cli.build_parser()._actions for o in a.option_strings}
    assert not {o for o in opts if re.search("pass|pwd|secret|user|dsn", o)}


@pytest.mark.parametrize(
    "argv", [["--sections", "nope"], ["--tablespace-warn", "120"], ["--health-only", "--security-only"]]
)
def test_cli_rejects_bad_arguments(argv):
    with pytest.raises(SystemExit) as exc:
        cli.main(argv)
    assert exc.value.code == 2


def test_cli_warn_above_crit(ora_env, capsys):
    assert cli.main(["--tablespace-warn", "96", "--no-banner"]) == 3
