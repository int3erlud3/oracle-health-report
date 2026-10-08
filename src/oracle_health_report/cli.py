"""Command line interface for oracle-health-report."""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from . import __version__
from .banner import maybe_print_banner, maybe_print_banner_for_info
from .checks import SECTION_KEYS, Thresholds, run_checks
from .config import ConfigError, from_env
from .report import Report, render_html, render_text

HEALTH = {"instance", "tablespaces", "invalid_objects", "sessions", "alert_log"}
SECURITY = set(SECTION_KEYS) - HEALTH

ENV_HELP = """\
connection (environment only - credentials are never accepted as arguments):
  ORACLE_DSN              e.g. dbhost:1521/ORCLPDB1 or a tnsnames.ora alias
  ORACLE_USER             monitoring account (needs CREATE SESSION + SELECT_CATALOG_ROLE)
  ORACLE_PASSWORD_FILE    file containing the password, mode 0600 (preferred)
  ORACLE_PASSWORD         password (alternative to ORACLE_PASSWORD_FILE)
  TNS_ADMIN               directory with tnsnames.ora / sqlnet.ora
  ORACLE_WALLET_LOCATION  wallet directory (ewallet.pem) for TCPS / mTLS
  ORACLE_WALLET_PASSWORD  wallet password, if the PEM wallet is encrypted

exit codes: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN (error or section not available)
"""


def _sections(value: str) -> set[str]:
    chosen = {v.strip() for v in value.split(",") if v.strip()}
    unknown = chosen - set(SECTION_KEYS)
    if unknown:
        raise argparse.ArgumentTypeError(f"unknown section(s): {', '.join(sorted(unknown))}")
    return chosen


def _pct(value: str) -> float:
    try:
        number = float(value)
    except ValueError:
        number = -1
    if not 0 < number <= 100:
        raise argparse.ArgumentTypeError("must be a percentage between 0 and 100")
    return number


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="oracle-health-report",
        description="Read-only Oracle Database health and security report (HTML, JSON or text).",
        epilog=ENV_HELP,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-f", "--format", choices=("html", "json", "text"), default="text")
    p.add_argument("-o", "--output", type=Path, help="write the report to this file (mode 0600)")
    scope = p.add_mutually_exclusive_group()
    scope.add_argument("--sections", type=_sections, help=f"comma-separated: {','.join(SECTION_KEYS)}")
    scope.add_argument("--health-only", action="store_true", help="skip the security sections")
    scope.add_argument("--security-only", action="store_true", help="only the security sections")
    p.add_argument("--tablespace-warn", type=_pct, default=85.0, metavar="PCT")
    p.add_argument("--tablespace-crit", type=_pct, default=95.0, metavar="PCT")
    p.add_argument("--alert-hours", type=int, default=24, metavar="H", help="alert log window (default 24)")
    p.add_argument("--expiry-days", type=int, default=14, metavar="D", help="warn about expiring passwords")
    p.add_argument("--timeout", type=int, default=60, metavar="S", help="per-query timeout in seconds")
    p.add_argument(
        "--no-banner", action="store_true", help="do not print the startup banner (or set NO_BANNER=1)"
    )
    p.add_argument("-V", "--version", action="version", version=f"%(prog)s {__version__}")
    return p


def write_private(path: Path, text: str) -> None:
    """Create/replace the file with mode 0600 and never follow a symlink."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as fh:
        fh.write(text)


def main(argv: Sequence[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    maybe_print_banner_for_info(argv)
    args = build_parser().parse_args(argv)
    if args.format != "json":  # never mix the banner with machine-readable output
        maybe_print_banner(args.no_banner)
    if args.tablespace_warn > args.tablespace_crit:
        print("error: --tablespace-warn must not exceed --tablespace-crit", file=sys.stderr)
        return 3
    only = args.sections or (HEALTH if args.health_only else SECURITY if args.security_only else None)
    thresholds = Thresholds(
        tablespace_warn=args.tablespace_warn,
        tablespace_crit=args.tablespace_crit,
        alert_hours=args.alert_hours,
        expiry_days=args.expiry_days,
    )
    try:
        cfg = from_env()
    except (ConfigError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3

    from .db import connect  # noqa: PLC0415

    try:
        db = connect(cfg, call_timeout_ms=args.timeout * 1000)
    except Exception as exc:  # driver errors are reported, not traced
        print(
            f"error: cannot connect to {cfg.dsn} as {cfg.user}: {str(exc).splitlines()[0]}", file=sys.stderr
        )
        return 3
    try:
        report = Report(run_checks(db.fetch, thresholds, only), target=f"{cfg.user}@{cfg.dsn}")
    finally:
        db.close()

    if args.format == "json":
        import json  # noqa: PLC0415

        text = json.dumps(report.to_dict(), indent=2)
    elif args.format == "html":
        text = render_html(report)
    else:
        text = render_text(report)
    if args.output:
        write_private(args.output, text + "\n")
        print(f"report written to {args.output} ({report.status})", file=sys.stderr)
    else:
        print(text)
    return report.exit_code


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
