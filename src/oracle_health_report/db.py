"""Thin database access layer: read-only transaction, named queries only."""

from __future__ import annotations

import re
from typing import Any

from .config import ConnectionConfig
from .queries import QUERIES

_READ_ONLY_SQL = re.compile(r"^\s*(SELECT|WITH)\b", re.IGNORECASE)
APP_NAME = "oracle-health-report"


def assert_read_only(sql: str) -> None:
    """Defence in depth: only single SELECT/WITH statements are ever executed."""
    if not _READ_ONLY_SQL.match(sql) or ";" in sql:
        raise ValueError("only single SELECT statements are allowed")


class Database:
    def __init__(self, connection: Any, call_timeout_ms: int = 60_000) -> None:
        self.conn = connection
        self.conn.call_timeout = call_timeout_ms
        self.conn.module = APP_NAME
        self.conn.action = "report"
        with self.conn.cursor() as cur:
            # Any DML in this transaction would fail with ORA-01456.
            cur.execute("SET TRANSACTION READ ONLY")

    def fetch(self, name: str, **params: Any) -> list[dict[str, Any]]:
        sql = QUERIES[name]
        assert_read_only(sql)
        with self.conn.cursor() as cur:
            cur.execute(sql, params)
            columns = [d[0].lower() for d in cur.description or ()]
            return [dict(zip(columns, row, strict=True)) for row in cur.fetchall()]

    def close(self) -> None:
        try:
            self.conn.rollback()
        finally:
            self.conn.close()


def connect(cfg: ConnectionConfig, call_timeout_ms: int = 60_000) -> Database:
    import oracledb  # noqa: PLC0415 - imported lazily so --help works without the driver

    conn = oracledb.connect(**cfg.connect_kwargs(), program=APP_NAME)
    return Database(conn, call_timeout_ms)
