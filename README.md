# oracle-health-report

[![CI](https://github.com/int3erlud3/oracle-health-report/actions/workflows/ci.yml/badge.svg)](https://github.com/int3erlud3/oracle-health-report/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

```text
                   _         _             _ _   _
   ___ _ _ __ _ __| |___ ___| |_  ___ __ _| | |_| |_
  / _ \ '_/ _` / _| / -_)___| ' \/ -_) _` | |  _| ' \
  \___/_| \__,_\__|_\___|   |_||_\___\__,_|_|\__|_||_|
                         _
   _ _ ___ _ __  ___ _ _| |_
  | '_/ -_) '_ \/ _ \ '_|  _|
  |_| \___| .__/\___/_|  \__|
          |_|

+====================================================================+
|  ORACLE HEALTH REPORT  ::  Database Health & Security Audit        |
+--------------------------------------------------------------------+
|  Read-only storage, sessions, alert log, privileges and audit      |
|  v1.0.0  -  Bastion Ops Toolkit  -  by int3erlud3                  |
+====================================================================+
```

A **read-only** health and security report for Oracle Database, written for the
morning check and for audits. It connects with **python-oracledb in thin mode** (no
Oracle Client installation needed), runs a fixed set of dictionary queries and
produces a **self-contained HTML page**, **JSON** for automation, or a short **text**
summary with monitoring-friendly exit codes.

## What is checked

| Section | Checks |
|---|---|
| Instance & database | instance status, open mode, **ARCHIVELOG mode** |
| Tablespace usage | used % of the *maximum* size (autoextend aware), incl. TEMP; warn 85 % / crit 95 % |
| Invalid objects | by owner and type, split into application vs. Oracle-maintained schemas |
| Sessions & locks | sessions/processes vs. limits, **blocked sessions** with blocker, event and wait time |
| Alert log | ORA-/TNS- messages from `V$DIAG_ALERT_EXT` in the last N hours; ORA-600/7445/4031/1578/257/19809/19815/1110/353 are critical |
| **Security: accounts** | open accounts with **default passwords**, open Oracle-maintained accounts, expired/expiring passwords |
| **Security: privileges** | non-default **DBA** grantees, `* ANY *` and other powerful system privileges, **PUBLIC** `EXECUTE` on the CIS package list (UTL_HTTP, UTL_FILE, DBMS_SQL, ...), system privileges/roles granted to PUBLIC |
| **Security: password profiles** | `FAILED_LOGIN_ATTEMPTS` (UNLIMITED / > 10), missing `PASSWORD_VERIFY_FUNCTION`, unlimited reuse (with `DEFAULT` inheritance resolved) |
| **Security: audit** | unified auditing mode, enabled unified audit policies, logon auditing, `AUDIT_SYS_OPERATIONS` in mixed mode |

If one view is not accessible, only that section is marked `UNKNOWN` and the rest of
the report is still produced.

## Safety by design

- **Read-only**: every statement is a single `SELECT` from [`queries.py`](src/oracle_health_report/queries.py),
  enforced by a guard, and the session starts with `SET TRANSACTION READ ONLY`.
  No PL/SQL, no DDL/DML, no dynamic SQL; parameters use bind variables.
- **Least privilege**: the monitoring user needs only `CREATE SESSION`,
  `SELECT_CATALOG_ROLE` and `SELECT` on three views that the role does not cover
  (`V_$DIAG_ALERT_EXT`, `DBA_USERS_WITH_DEFPWD`, `AUDIT_UNIFIED_ENABLED_POLICIES`) – see
  [`sql/create_monitoring_user.sql`](sql/create_monitoring_user.sql). CI verifies that every
  section works with exactly these privileges.
- **No credentials on the command line** (they would be visible in `ps` and shell
  history): connection settings come from the environment, a `chmod 600` password file
  or a wallet. There are intentionally no `--user`/`--password` options.
- **Safe HTML**: Jinja2 with `autoescape=True` (alert log text and object names are
  untrusted), a strict `Content-Security-Policy` (`default-src 'none'`, the inline CSS
  allowed by its SHA-256 hash), no JavaScript, no external resources.
- Reports written with `-o` are created with mode `0600` and never through a symlink.
- Per-query timeout (`--timeout`, default 60 s) and module/action tags so the session is
  easy to identify in `V$SESSION`.

## Installation

```bash
git clone https://github.com/int3erlud3/oracle-health-report.git
cd oracle-health-report
python3 -m pip install .          # Python 3.10+, installs oracledb and Jinja2
```

## Configuration

| Variable | Purpose |
|---|---|
| `ORACLE_DSN` | Easy Connect (`dbhost:1521/ORCLPDB1`) or a `tnsnames.ora` alias |
| `ORACLE_USER` | the monitoring account |
| `ORACLE_PASSWORD_FILE` | file containing only the password, mode `0600` (preferred) |
| `ORACLE_PASSWORD` | alternative to the password file |
| `TNS_ADMIN` | directory with `tnsnames.ora` / `sqlnet.ora` |
| `ORACLE_WALLET_LOCATION` | wallet directory (`ewallet.pem`) for TCPS / mutual TLS |
| `ORACLE_WALLET_PASSWORD` | password of an encrypted PEM wallet |

An empty template is provided in [`.env.example`](.env.example) – never commit a filled-in copy.
Note: thin mode does not support Secure External Password Store (`/@alias`) logins;
use the password file, or thick mode if SEPS is mandatory.

## Usage

```bash
export ORACLE_DSN=db1:1521/ORCLPDB1 ORACLE_USER=health_monitor
export ORACLE_PASSWORD_FILE=~/.config/oracle-health-report/password   # chmod 600

oracle-health-report                                   # text summary
oracle-health-report -f html -o /var/reports/db1.html  # full HTML report
oracle-health-report -f json | jq '.sections[] | {key, status}'
oracle-health-report --security-only                   # audit view only
oracle-health-report --sections tablespaces,alert_log --alert-hours 6
```

Example text output:

```text
Oracle health report for health_monitor@db1:1521/ORCLPDB1  -  2026-10-08 09:25 UTC

[OK      ] Instance & database
[WARNING ] Tablespace usage
           - WARNING: tablespace USERS is 91.3% full
[OK      ] Invalid objects
[OK      ] Sessions & locks
[WARNING ] Alert log errors (last 24 h)
           - WARNING: 1 other ORA-/TNS- message(s) in the alert log
[OK      ] Security: accounts
[WARNING ] Security: privileges
           - WARNING: APPADMIN has the DBA role
           - WARNING: PUBLIC can execute UTL_HTTP (network/file access package)
[CRITICAL] Security: password profiles
           - CRITICAL: profile APP: FAILED_LOGIN_ATTEMPTS is UNLIMITED (no brute-force lockout)
           - CRITICAL: profile DEFAULT: FAILED_LOGIN_ATTEMPTS is UNLIMITED (no brute-force lockout)
[OK      ] Security: audit configuration

OVERALL: CRITICAL
```

### Exit codes

| Code | Meaning |
|---|---|
| 0 | OK |
| 1 | at least one WARNING |
| 2 | at least one CRITICAL finding |
| 3 | UNKNOWN: configuration/connection error or a section could not be read |

### Options

| Option | Default | Description |
|---|---|---|
| `-f, --format` | `text` | `text`, `html` or `json` |
| `-o, --output FILE` | stdout | write the report to a file (mode 0600) |
| `--sections LIST` / `--health-only` / `--security-only` | all | limit the report |
| `--tablespace-warn` / `--tablespace-crit` | 85 / 95 | tablespace thresholds in % |
| `--alert-hours H` | 24 | alert log window |
| `--expiry-days D` | 14 | report passwords expiring within D days |
| `--timeout S` | 60 | per-query timeout |
| `--no-banner` | | suppress the banner (also `NO_BANNER=1`) |

The banner is printed to **stderr** only when stderr is a terminal, and never with
`--format json`.

## Scheduling example

```ini
# /etc/systemd/system/oracle-health-report.service
[Service]
Type=oneshot
User=oramon
EnvironmentFile=/etc/oracle-health-report/env        # ORACLE_DSN, ORACLE_USER, ORACLE_PASSWORD_FILE
ExecStart=/usr/local/bin/oracle-health-report --no-banner -f html -o /var/lib/oramon/report.html
NoNewPrivileges=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/oramon
PrivateTmp=yes
```

## Development

```bash
python3 -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
make lint test security
```

Unit tests use a fake python-oracledb connection with canned rows (75+ tests, ~97 %
coverage), including HTML-escaping and CSP checks. The CI `integration` job starts
`gvenzl/oracle-free` (Oracle Database 23ai Free), creates a least-privilege user with
throw-away masked passwords and runs the full report against it
(`OHR_INTEGRATION=1 pytest -m integration`).

## License

[MIT](LICENSE)
