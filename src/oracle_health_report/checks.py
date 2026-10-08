"""Turn query results into report sections with findings and a status."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

OK, WARNING, CRITICAL, UNKNOWN = "OK", "WARNING", "CRITICAL", "UNKNOWN"
RANK = {OK: 0, WARNING: 1, CRITICAL: 2, UNKNOWN: 3}
Fetch = Callable[..., list[dict[str, Any]]]

CRITICAL_ALERT_CODES = (
    "ORA-00600",
    "ORA-07445",
    "ORA-04031",
    "ORA-01578",
    "ORA-00257",
    "ORA-19809",
    "ORA-19815",
    "ORA-01110",
    "ORA-00353",
)
CRITICAL_PRIVILEGES = {
    "GRANT ANY PRIVILEGE",
    "GRANT ANY ROLE",
    "GRANT ANY OBJECT PRIVILEGE",
    "BECOME USER",
    "EXEMPT ACCESS POLICY",
    "EXECUTE ANY PROCEDURE",
    "CREATE ANY PROCEDURE",
    "ALTER ANY PROCEDURE",
    "ALTER USER",
    "ALTER SYSTEM",
    "SELECT ANY DICTIONARY",
}
NETWORK_PACKAGES = {"UTL_HTTP", "UTL_TCP", "UTL_SMTP", "UTL_INADDR", "UTL_MAIL", "UTL_FILE", "DBMS_LDAP"}
EXPECTED_OPEN_MAINTAINED = {"SYS", "SYSTEM"}


@dataclass
class Thresholds:
    tablespace_warn: float = 85.0
    tablespace_crit: float = 95.0
    sessions_warn: float = 85.0
    sessions_crit: float = 95.0
    blocking_crit_s: int = 300
    alert_hours: int = 24
    expiry_days: int = 14
    max_failed_logins: int = 10


@dataclass
class Finding:
    severity: str
    message: str


@dataclass
class Table:
    title: str
    rows: list[dict[str, Any]]


@dataclass
class Section:
    key: str
    title: str
    tables: list[Table] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    error: str = ""

    @property
    def status(self) -> str:
        if self.error:
            return UNKNOWN
        return max((f.severity for f in self.findings), key=RANK.__getitem__, default=OK)

    def add(self, severity: str, message: str) -> None:
        self.findings.append(Finding(severity, message))


def worst(statuses: list[str]) -> str:
    return max(statuses, key=RANK.__getitem__, default=OK)


def _num(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


# ---- health ------------------------------------------------------------------
def check_instance(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("instance", "Instance & database")
    rows = fetch("instance")
    s.tables.append(Table("Instance", rows))
    for r in rows:
        if r.get("status") != "OPEN":
            s.add(CRITICAL, f"instance status is {r.get('status')}")
        if r.get("log_mode") != "ARCHIVELOG":
            s.add(WARNING, "database runs in NOARCHIVELOG mode: no point-in-time recovery possible")
        if r.get("open_mode") not in ("READ WRITE", None) and r.get("database_role") == "PRIMARY":
            s.add(WARNING, f"primary database open mode is {r.get('open_mode')}")
    return s


def check_tablespaces(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("tablespaces", "Tablespace usage")
    rows = fetch("tablespaces")
    s.tables.append(Table("Usage (of maximum size incl. autoextend)", rows))
    for r in rows:
        pct = _num(r.get("used_pct"))
        if pct >= t.tablespace_crit:
            s.add(CRITICAL, f"tablespace {r['tablespace_name']} is {pct:.1f}% full")
        elif pct >= t.tablespace_warn:
            s.add(WARNING, f"tablespace {r['tablespace_name']} is {pct:.1f}% full")
    return s


def check_invalid_objects(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("invalid_objects", "Invalid objects")
    rows = fetch("invalid_objects")
    s.tables.append(Table("Invalid objects by owner and type", rows))
    total = sum(int(_num(r.get("invalid_count"))) for r in rows)
    app = sum(int(_num(r.get("invalid_count"))) for r in rows if r.get("oracle_maintained") != "Y")
    if app:
        s.add(WARNING, f"{app} invalid object(s) in application schemas")
    if total - app:
        s.add(WARNING, f"{total - app} invalid object(s) in Oracle-maintained schemas (run utlrp.sql?)")
    return s


def check_sessions(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("sessions", "Sessions & locks")
    usage = fetch("session_usage")
    blocking = fetch("blocking_sessions")
    s.tables += [Table("Usage", usage), Table("Blocked sessions", blocking)]
    for r in usage:
        for used, limit, label in (
            ("sessions", "sessions_limit", "sessions"),
            ("processes", "processes_limit", "processes"),
        ):
            lim = _num(r.get(limit))
            pct = 100 * _num(r.get(used)) / lim if lim else 0
            if pct >= t.sessions_crit:
                s.add(CRITICAL, f"{label} at {pct:.0f}% of limit")
            elif pct >= t.sessions_warn:
                s.add(WARNING, f"{label} at {pct:.0f}% of limit")
    for r in blocking:
        sev = CRITICAL if _num(r.get("wait_s")) >= t.blocking_crit_s else WARNING
        s.add(
            sev,
            f"session {r.get('sid')} ({r.get('username')}) blocked by {r.get('blocking_session')} "
            f"for {int(_num(r.get('wait_s')))}s on '{r.get('event')}'",
        )
    return s


def check_alert_log(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("alert_log", f"Alert log errors (last {t.alert_hours} h)")
    rows = fetch("alert_log", hours=t.alert_hours)
    s.tables.append(Table("Recent messages", rows))
    critical = [r for r in rows if any(c in str(r.get("message_text")) for c in CRITICAL_ALERT_CODES)]
    if critical:
        codes = sorted({c for r in critical for c in CRITICAL_ALERT_CODES if c in str(r.get("message_text"))})
        s.add(CRITICAL, f"{len(critical)} critical alert log message(s): {', '.join(codes)}")
    if len(rows) > len(critical):
        s.add(WARNING, f"{len(rows) - len(critical)} other ORA-/TNS- message(s) in the alert log")
    return s


# ---- security ------------------------------------------------------------------
def check_accounts(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("accounts", "Security: accounts")
    defpwd = fetch("default_passwords")
    maintained = fetch("open_maintained_accounts")
    expiring = fetch("expiring_accounts", days=t.expiry_days)
    s.tables += [
        Table("Accounts with default passwords", defpwd),
        Table("Open Oracle-maintained accounts", maintained),
        Table(f"Expired or expiring within {t.expiry_days} days", expiring),
    ]
    for r in defpwd:
        if r.get("account_status") == "OPEN":
            s.add(CRITICAL, f"account {r['username']} is OPEN with a default password")
    for r in maintained:
        if r.get("username") not in EXPECTED_OPEN_MAINTAINED:
            s.add(WARNING, f"Oracle-maintained account {r['username']} is open")
    for r in expiring:
        status = str(r.get("account_status"))
        if status == "OPEN":
            s.add(WARNING, f"password of {r['username']} expires on {r.get('expiry_date')}")
        elif "EXPIRED" in status and "LOCKED" not in status:
            s.add(WARNING, f"account {r['username']} is {status}")
    return s


def check_privileges(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("privileges", "Security: privileges")
    dba = fetch("dba_grantees")
    powerful = fetch("powerful_privileges")
    pub_exec = fetch("public_execute_grants")
    pub_sys = fetch("public_sys_privs")
    s.tables += [
        Table("Non-default grantees of DBA", dba),
        Table("ANY and other powerful system privileges", powerful),
        Table("EXECUTE granted to PUBLIC (CIS list)", pub_exec),
        Table("System privileges/roles granted to PUBLIC", pub_sys),
    ]
    for r in dba:
        s.add(
            WARNING,
            f"{r['grantee']} has the DBA role"
            + (" WITH ADMIN OPTION" if r.get("admin_option") == "YES" else ""),
        )
    for r in powerful:
        sev = CRITICAL if r.get("privilege") in CRITICAL_PRIVILEGES else WARNING
        s.add(sev, f"{r['grantee']} has {r['privilege']}")
    for r in pub_exec:
        kind = "network/file access" if r.get("object_name") in NETWORK_PACKAGES else "powerful"
        s.add(WARNING, f"PUBLIC can execute {r['object_name']} ({kind} package)")
    for r in pub_sys:
        s.add(CRITICAL, f"PUBLIC has {r['privilege']}")
    return s


def _profile_limits(rows: list[dict[str, Any]]) -> dict[str, dict[str, str]]:
    profiles: dict[str, dict[str, str]] = {}
    for r in rows:
        profiles.setdefault(r["profile"], {})[r["resource_name"]] = str(r.get("limit"))
    default = profiles.get("DEFAULT", {})
    for limits in profiles.values():
        for name, value in limits.items():
            if value == "DEFAULT":
                limits[name] = default.get(name, "UNLIMITED")
    return profiles


def check_password_profiles(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("password_profiles", "Security: password profiles")
    rows = fetch("profile_limits")
    s.tables.append(Table("Password limits", rows))
    for profile, limits in sorted(_profile_limits(rows).items()):
        fla = limits.get("FAILED_LOGIN_ATTEMPTS", "UNLIMITED")
        if fla == "UNLIMITED":
            s.add(CRITICAL, f"profile {profile}: FAILED_LOGIN_ATTEMPTS is UNLIMITED (no brute-force lockout)")
        elif fla.isdigit() and int(fla) > t.max_failed_logins:
            s.add(WARNING, f"profile {profile}: FAILED_LOGIN_ATTEMPTS {fla} > {t.max_failed_logins}")
        if limits.get("PASSWORD_VERIFY_FUNCTION", "NULL") in ("NULL", "None", "UNLIMITED"):
            s.add(WARNING, f"profile {profile}: no PASSWORD_VERIFY_FUNCTION (no complexity check)")
        if (
            limits.get("PASSWORD_REUSE_MAX") == "UNLIMITED"
            and limits.get("PASSWORD_REUSE_TIME") == "UNLIMITED"
        ):
            s.add(WARNING, f"profile {profile}: passwords may be reused immediately")
    return s


def check_audit(fetch: Fetch, t: Thresholds) -> Section:
    s = Section("audit", "Security: audit configuration")
    settings = fetch("audit_settings")
    policies = fetch("audit_policies")
    s.tables += [Table("Settings", settings), Table("Enabled unified audit policies", policies)]
    cfg = {str(r["name"]).lower(): str(r.get("value")).upper() for r in settings}
    pure_unified = cfg.get("unified_auditing") == "TRUE"
    if not policies:
        traditional = cfg.get("audit_trail", "NONE") not in ("NONE", "FALSE")
        sev = WARNING if traditional and not pure_unified else CRITICAL
        s.add(sev, "no unified audit policies are enabled")
    elif not any("LOGON" in str(p.get("policy_name")).upper() for p in policies):
        s.add(WARNING, "no enabled policy audits logons (e.g. ORA_LOGON_FAILURES)")
    if not pure_unified and cfg.get("audit_sys_operations") != "TRUE":
        s.add(WARNING, "mixed-mode auditing with AUDIT_SYS_OPERATIONS=FALSE: SYS actions are not audited")
    return s


HEALTH_CHECKS = (check_instance, check_tablespaces, check_invalid_objects, check_sessions, check_alert_log)
SECURITY_CHECKS = (check_accounts, check_privileges, check_password_profiles, check_audit)
ALL_CHECKS = HEALTH_CHECKS + SECURITY_CHECKS
SECTION_KEYS = (
    "instance",
    "tablespaces",
    "invalid_objects",
    "sessions",
    "alert_log",
    "accounts",
    "privileges",
    "password_profiles",
    "audit",
)


def run_checks(fetch: Fetch, t: Thresholds, only: set[str] | None = None) -> list[Section]:
    sections = []
    for key, check in zip(SECTION_KEYS, ALL_CHECKS, strict=True):
        if only and key not in only:
            continue
        try:
            sections.append(check(fetch, t))
        except Exception as exc:  # one failing view/driver error must not abort the report
            sections.append(Section(key, key.replace("_", " ").title(), error=_error_text(exc)))
    return sections


def _error_text(exc: BaseException) -> str:
    text = str(exc).splitlines()[0] if str(exc) else type(exc).__name__
    return text[:300]
