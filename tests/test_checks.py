from datetime import datetime

import pytest

from oracle_health_report import checks
from oracle_health_report.checks import CRITICAL, OK, UNKNOWN, WARNING, Thresholds, run_checks

T = Thresholds()


def by_key(sections):
    return {s.key: s for s in sections}


def test_healthy_database_is_ok(fake_db):
    sections = run_checks(fake_db.fetch, T)
    assert [s.key for s in sections] == list(checks.SECTION_KEYS)
    assert {s.key: s.status for s in sections} == dict.fromkeys(checks.SECTION_KEYS, OK)


def test_only_selected_sections(fake_db):
    sections = run_checks(fake_db.fetch, T, only={"tablespaces", "audit"})
    assert [s.key for s in sections] == ["tablespaces", "audit"]


def test_noarchivelog_and_closed_instance(fake_db, data):
    data["instance"][0].update(log_mode="NOARCHIVELOG", status="MOUNTED")
    s = checks.check_instance(fake_db.fetch, T)
    assert s.status == CRITICAL
    assert any("NOARCHIVELOG" in f.message for f in s.findings)


@pytest.mark.parametrize(("pct", "status"), [(84.9, OK), (85, WARNING), (96.5, CRITICAL)])
def test_tablespace_thresholds(fake_db, data, pct, status):
    data["tablespaces"][1]["used_pct"] = pct
    assert checks.check_tablespaces(fake_db.fetch, T).status == status


def test_invalid_objects_split_by_maintained(fake_db, data):
    data["invalid_objects"] = [
        {"owner": "APP", "object_type": "PACKAGE BODY", "invalid_count": 3, "oracle_maintained": "N"},
        {"owner": "SYS", "object_type": "VIEW", "invalid_count": 1, "oracle_maintained": "Y"},
    ]
    s = checks.check_invalid_objects(fake_db.fetch, T)
    assert s.status == WARNING
    assert [f.message for f in s.findings] == [
        "3 invalid object(s) in application schemas",
        "1 invalid object(s) in Oracle-maintained schemas (run utlrp.sql?)",
    ]


def test_sessions_usage_and_blocking(fake_db, data):
    data["session_usage"][0]["sessions"] = 900
    data["blocking_sessions"] = [
        {"sid": 42, "username": "APP", "blocking_session": 17, "event": "enq: TX - row lock", "wait_s": 30},
        {"sid": 43, "username": "APP", "blocking_session": 17, "event": "enq: TX - row lock", "wait_s": 900},
    ]
    s = checks.check_sessions(fake_db.fetch, T)
    sev = [f.severity for f in s.findings]
    assert sev == [WARNING, WARNING, CRITICAL]
    assert "blocked by 17 for 900s" in s.findings[-1].message


def test_alert_log_classification(fake_db, data):
    data["alert_log"] = [
        {"originating_timestamp": datetime(2026, 10, 8), "message_text": "ORA-00600: internal error code"},
        {"originating_timestamp": datetime(2026, 10, 8), "message_text": "ORA-12170: TNS:Connect timeout"},
    ]
    s = checks.check_alert_log(fake_db.fetch, T)
    assert s.status == CRITICAL
    assert "ORA-00600" in s.findings[0].message
    assert s.findings[1].severity == WARNING


def test_accounts(fake_db, data):
    data["default_passwords"].append({"username": "DBSNMP", "account_status": "OPEN"})
    data["open_maintained_accounts"].append({"username": "OUTLN", "account_status": "OPEN"})
    data["expiring_accounts"] = [
        {"username": "APP", "account_status": "OPEN", "expiry_date": "2026-10-10", "profile": "DEFAULT"},
        {"username": "OLD", "account_status": "EXPIRED", "expiry_date": "2026-01-01", "profile": "DEFAULT"},
        {"username": "GONE", "account_status": "EXPIRED & LOCKED", "expiry_date": None, "profile": "DEFAULT"},
    ]
    s = checks.check_accounts(fake_db.fetch, T)
    msgs = [(f.severity, f.message) for f in s.findings]
    assert (CRITICAL, "account DBSNMP is OPEN with a default password") in msgs
    assert (WARNING, "Oracle-maintained account OUTLN is open") in msgs
    assert not any("SCOTT" in m or "GONE" in m or "account SYS " in m for _, m in msgs)
    assert len(msgs) == 4


def test_privileges(fake_db, data):
    data["dba_grantees"] = [{"grantee": "APPADMIN", "admin_option": "YES"}]
    data["powerful_privileges"] = [
        {"grantee": "ETL", "privilege": "SELECT ANY TABLE", "admin_option": "NO"},
        {"grantee": "DEV", "privilege": "GRANT ANY PRIVILEGE", "admin_option": "NO"},
    ]
    data["public_execute_grants"] = [{"object_name": "UTL_HTTP", "privilege": "EXECUTE"}]
    data["public_sys_privs"] = [{"privilege": "CREATE SESSION"}]
    s = checks.check_privileges(fake_db.fetch, T)
    msgs = {f.message: f.severity for f in s.findings}
    assert msgs["APPADMIN has the DBA role WITH ADMIN OPTION"] == WARNING
    assert msgs["ETL has SELECT ANY TABLE"] == WARNING
    assert msgs["DEV has GRANT ANY PRIVILEGE"] == CRITICAL
    assert msgs["PUBLIC can execute UTL_HTTP (network/file access package)"] == WARNING
    assert msgs["PUBLIC has CREATE SESSION"] == CRITICAL


def test_password_profiles_inherit_default(fake_db, data):
    data["profile_limits"] = [
        {"profile": "DEFAULT", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "UNLIMITED"},
        {"profile": "DEFAULT", "resource_name": "PASSWORD_VERIFY_FUNCTION", "limit": "NULL"},
        {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_MAX", "limit": "UNLIMITED"},
        {"profile": "DEFAULT", "resource_name": "PASSWORD_REUSE_TIME", "limit": "UNLIMITED"},
        {"profile": "APP", "resource_name": "FAILED_LOGIN_ATTEMPTS", "limit": "50"},
        {"profile": "APP", "resource_name": "PASSWORD_VERIFY_FUNCTION", "limit": "DEFAULT"},
    ]
    s = checks.check_password_profiles(fake_db.fetch, T)
    msgs = [(f.severity, f.message) for f in s.findings]
    assert (WARNING, "profile APP: FAILED_LOGIN_ATTEMPTS 50 > 10") in msgs
    assert (WARNING, "profile APP: no PASSWORD_VERIFY_FUNCTION (no complexity check)") in msgs
    assert (CRITICAL, "profile DEFAULT: FAILED_LOGIN_ATTEMPTS is UNLIMITED (no brute-force lockout)") in msgs
    assert (WARNING, "profile DEFAULT: passwords may be reused immediately") in msgs


@pytest.mark.parametrize(
    ("unified", "trail", "policies", "status"),
    [
        ("TRUE", "NONE", [], CRITICAL),
        ("FALSE", "DB", [], WARNING),
        ("TRUE", "NONE", [{"policy_name": "ORA_SECURECONFIG"}], WARNING),
    ],
)
def test_audit(fake_db, data, unified, trail, policies, status):
    data["audit_settings"] = [
        {"name": "unified_auditing", "value": unified},
        {"name": "audit_trail", "value": trail},
        {"name": "audit_sys_operations", "value": "TRUE"},
    ]
    data["audit_policies"] = policies
    assert checks.check_audit(fake_db.fetch, T).status == status


def test_mixed_mode_without_sys_audit(fake_db, data):
    data["audit_settings"] = [{"name": "unified_auditing", "value": "FALSE"}]
    s = checks.check_audit(fake_db.fetch, T)
    assert any("AUDIT_SYS_OPERATIONS" in f.message for f in s.findings)


class FakeDatabaseError(Exception):
    pass


def test_failing_query_becomes_unknown_section(fake_db, fake_conn):
    fake_conn.fail["audit_policies"] = FakeDatabaseError("ORA-00942: table or view does not exist\nmore")
    sections = by_key(run_checks(fake_db.fetch, T))
    assert sections["audit"].status == UNKNOWN
    assert sections["audit"].error == "ORA-00942: table or view does not exist"
    assert sections["tablespaces"].status == OK
