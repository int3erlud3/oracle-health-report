import sys
import types

import pytest

from oracle_health_report import db
from oracle_health_report.config import ConfigError, from_env
from oracle_health_report.queries import CIS_PUBLIC_PACKAGES, QUERIES

BASE = {"ORACLE_DSN": "db1/FREEPDB1", "ORACLE_USER": "mon"}


def test_requires_dsn_and_user():
    with pytest.raises(ConfigError, match="ORACLE_DSN"):
        from_env({"ORACLE_USER": "x", "ORACLE_PASSWORD": "y"})


def test_requires_password():
    with pytest.raises(ConfigError, match="no password"):
        from_env(BASE)


def test_password_from_env_is_not_in_repr():
    cfg = from_env({**BASE, "ORACLE_PASSWORD": "s3cr3t-value"})
    assert cfg.password == "s3cr3t-value"
    assert "s3cr3t-value" not in repr(cfg)


def test_password_file_must_be_private(tmp_path):
    pw = tmp_path / "pw"
    pw.write_text("abc\n")
    pw.chmod(0o644)
    with pytest.raises(ConfigError, match="chmod 600"):
        from_env({**BASE, "ORACLE_PASSWORD_FILE": str(pw)})
    pw.chmod(0o600)
    assert from_env({**BASE, "ORACLE_PASSWORD_FILE": str(pw)}).password == "abc"


def test_password_and_file_are_exclusive(tmp_path):
    with pytest.raises(ConfigError, match="not both"):
        from_env({**BASE, "ORACLE_PASSWORD": "a", "ORACLE_PASSWORD_FILE": str(tmp_path / "x")})


def test_wallet_settings_are_passed_to_driver():
    cfg = from_env(
        {
            **BASE,
            "ORACLE_PASSWORD": "a",
            "TNS_ADMIN": "/etc/oracle",
            "ORACLE_WALLET_LOCATION": "/etc/oracle/wallet",
            "ORACLE_WALLET_PASSWORD": "w",
        }
    )
    kw = cfg.connect_kwargs()
    assert kw["config_dir"] == "/etc/oracle"
    assert kw["wallet_location"] == "/etc/oracle/wallet"
    assert kw["wallet_password"] == "w"
    assert "wallet_location" not in from_env({**BASE, "ORACLE_PASSWORD": "a"}).connect_kwargs()


@pytest.mark.parametrize("name", sorted(QUERIES))
def test_every_query_is_a_single_select(name):
    db.assert_read_only(QUERIES[name])
    sql = QUERIES[name].upper()
    for word in ("INSERT ", "UPDATE ", "DELETE ", "MERGE ", "DROP ", "ALTER ", "GRANT ", "EXECUTE IMMEDIATE"):
        assert word not in sql.replace("'ALTER ", "").replace("'GRANT ", "").replace("'DROP ", "")


@pytest.mark.parametrize(
    "sql", ["DELETE FROM t", "SELECT 1 FROM dual; DROP TABLE t", "BEGIN NULL; END;", "  update t set a=1"]
)
def test_guard_rejects_non_select(sql):
    with pytest.raises(ValueError, match="only single SELECT"):
        db.assert_read_only(sql)


def test_cis_package_list_matches_sql():
    for pkg in CIS_PUBLIC_PACKAGES:
        assert f"'{pkg}'" in QUERIES["public_execute_grants"]


def test_database_uses_read_only_transaction(fake_db, fake_conn):
    assert fake_conn.executed[0][0] == "SET TRANSACTION READ ONLY"
    assert fake_conn.module == "oracle-health-report"
    rows = fake_db.fetch("tablespaces")
    assert rows[0]["tablespace_name"] == "SYSTEM"
    fake_db.fetch("alert_log", hours=6)
    assert fake_conn.executed[-1][1] == {"hours": 6}
    fake_db.close()
    assert fake_conn.rolled_back and fake_conn.closed


def test_connect_uses_thin_driver_kwargs(monkeypatch, fake_conn):
    seen = {}

    def fake_connect(**kwargs):
        seen.update(kwargs)
        return fake_conn

    monkeypatch.setitem(sys.modules, "oracledb", types.SimpleNamespace(connect=fake_connect))
    cfg = from_env({**BASE, "ORACLE_PASSWORD": "a"})
    database = db.connect(cfg, call_timeout_ms=5000)
    assert seen["dsn"] == "db1/FREEPDB1" and seen["user"] == "mon" and seen["program"] == db.APP_NAME
    assert database.conn.call_timeout == 5000
