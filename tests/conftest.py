"""Shared fixtures: a fake python-oracledb connection that serves canned rows."""

from __future__ import annotations

import copy
from datetime import datetime

import pytest

from oracle_health_report import db as db_module

HEALTHY: dict[str, list[dict]] = {
    "instance": [
        {
            "instance_name": "FREE",
            "host_name": "db1",
            "version_full": "23.6.0.24.10",
            "status": "OPEN",
            "startup_time": datetime(2026, 10, 1, 6, 0),
            "db_name": "FREE",
            "log_mode": "ARCHIVELOG",
            "open_mode": "READ WRITE",
            "database_role": "PRIMARY",
        }
    ],
    "tablespaces": [
        {"tablespace_name": "SYSTEM", "used_mb": 700, "max_mb": 32768, "used_pct": 2.1},
        {"tablespace_name": "USERS", "used_mb": 50, "max_mb": 1000, "used_pct": 5.0},
    ],
    "invalid_objects": [],
    "session_usage": [{"sessions": 80, "sessions_limit": 1000, "processes": 70, "processes_limit": 600}],
    "blocking_sessions": [],
    "alert_log": [],
    "default_passwords": [{"username": "SCOTT", "account_status": "EXPIRED & LOCKED"}],
    "open_maintained_accounts": [{"username": "SYS", "account_status": "OPEN"}],
    "expiring_accounts": [],
    "dba_grantees": [],
    "powerful_privileges": [],
    "public_execute_grants": [],
    "public_sys_privs": [],
    "profile_limits": [
        {"profile": "DEFAULT", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "5"},
        {
            "profile": "DEFAULT",
            "resource_name": "PASSWORD_VERIFY_FUNCTION",
            "limit": "ORA12C_VERIFY_FUNCTION",
        },
        {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_MAX", "limit": "10"},
        {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_TIME", "limit": "365"},
        {"profile": "APP", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "DEFAULT"},
        {"profile": "APP", "resource_name": "PASSWORD_VERIFY_FUNCTION", "limit": "DEFAULT"},
    ],
    "audit_settings": [
        {"name": "unified_auditing", "value": "TRUE"},
        {"name": "audit_trail", "value": "NONE"},
    ],
    "audit_policies": [
        {"policy_name": "ORA_LOGON_FAILURES", "enabled_option": "BY USER", "entity_name": "ALL USERS"},
        {"policy_name": "ORA_SECURECONFIG", "enabled_option": "BY USER", "entity_name": "ALL USERS"},
    ],
}


class FakeCursor:
    def __init__(self, conn):
        self.conn = conn
        self.description = None
        self._rows: list[tuple] = []

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False

    def execute(self, sql, params=None):
        self.conn.executed.append((sql, params))
        if sql.strip().upper().startswith("SET TRANSACTION"):
            return
        name = next(k for k, v in self.conn.queries.items() if v == sql)
        if name in self.conn.fail:
            raise self.conn.fail[name]
        rows = self.conn.data[name]
        cols = list(rows[0].keys()) if rows else ["dummy"]
        self.description = [(c.upper(),) for c in cols]
        self._rows = [tuple(r[c] for c in cols) for r in rows]

    def fetchall(self):
        return self._rows


class FakeConnection:
    def __init__(self, data, fail=None):
        from oracle_health_report.queries import QUERIES

        self.queries = QUERIES
        self.data = data
        self.fail = fail or {}
        self.executed: list[tuple] = []
        self.closed = self.rolled_back = False

    def cursor(self):
        return FakeCursor(self)

    def rollback(self):
        self.rolled_back = True

    def close(self):
        self.closed = True


@pytest.fixture
def data():
    return copy.deepcopy(HEALTHY)


@pytest.fixture
def fake_conn(data):
    return FakeConnection(data)


@pytest.fixture
def fake_db(fake_conn):
    return db_module.Database(fake_conn)


@pytest.fixture
def ora_env(monkeypatch, tmp_path):
    for var in ("ORACLE_PASSWORD", "TNS_ADMIN", "ORACLE_WALLET_LOCATION", "ORACLE_WALLET_PASSWORD"):
        monkeypatch.delenv(var, raising=False)
    pw = tmp_path / "pw"
    pw.write_text("not-a-real-password\n")
    pw.chmod(0o600)
    monkeypatch.setenv("ORACLE_DSN", "db1:1521/FREEPDB1")
    monkeypatch.setenv("ORACLE_USER", "health_monitor")
    monkeypatch.setenv("ORACLE_PASSWORD_FILE", str(pw))
    return pw


@pytest.fixture
def patched_connect(monkeypatch, ora_env, fake_conn):
    calls = []

    def fake_connect(cfg, call_timeout_ms=60_000):
        calls.append((cfg, call_timeout_ms))
        return db_module.Database(fake_conn, call_timeout_ms)

    monkeypatch.setattr(db_module, "connect", fake_connect)
    fake_conn.calls = calls
    return fake_conn
