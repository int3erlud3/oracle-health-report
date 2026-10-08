"""Connection settings from the environment (never from command-line arguments).

Command-line arguments are visible to every local user via ``ps`` and end up in
shell history, so credentials are only accepted from environment variables, a
password file with restrictive permissions, or a wallet directory.
"""

from __future__ import annotations

import os
import stat
from collections.abc import Mapping
from dataclasses import dataclass, field
from pathlib import Path


class ConfigError(ValueError):
    pass


@dataclass(frozen=True)
class ConnectionConfig:
    dsn: str
    user: str
    password: str = field(repr=False)
    config_dir: str | None = None
    wallet_location: str | None = None
    wallet_password: str | None = field(default=None, repr=False)

    def connect_kwargs(self) -> dict:
        kwargs = {"user": self.user, "password": self.password, "dsn": self.dsn}
        if self.config_dir:
            kwargs["config_dir"] = self.config_dir
        if self.wallet_location:
            kwargs["wallet_location"] = self.wallet_location
        if self.wallet_password:
            kwargs["wallet_password"] = self.wallet_password
        return kwargs


def read_password_file(path: Path) -> str:
    st = path.stat()
    if st.st_mode & (stat.S_IRWXG | stat.S_IRWXO):
        raise ConfigError(f"{path} must not be accessible by group/others (chmod 600)")
    return path.read_text(encoding="utf-8").rstrip("\r\n")


def from_env(env: Mapping[str, str] | None = None) -> ConnectionConfig:
    env = os.environ if env is None else env
    dsn = env.get("ORACLE_DSN", "").strip()
    user = env.get("ORACLE_USER", "").strip()
    if not dsn or not user:
        raise ConfigError("set ORACLE_DSN and ORACLE_USER (see .env.example)")
    password = env.get("ORACLE_PASSWORD", "")
    pw_file = env.get("ORACLE_PASSWORD_FILE", "").strip()
    if pw_file:
        if password:
            raise ConfigError("set either ORACLE_PASSWORD or ORACLE_PASSWORD_FILE, not both")
        password = read_password_file(Path(pw_file))
    if not password:
        raise ConfigError("no password: set ORACLE_PASSWORD_FILE (preferred) or ORACLE_PASSWORD")
    return ConnectionConfig(
        dsn=dsn,
        user=user,
        password=password,
        config_dir=env.get("TNS_ADMIN") or None,
        wallet_location=env.get("ORACLE_WALLET_LOCATION") or None,
        wallet_password=env.get("ORACLE_WALLET_PASSWORD") or None,
    )
