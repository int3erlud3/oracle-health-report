"""All SQL used by the report. Every statement is a single read-only SELECT.

The required privileges are covered by ``SELECT_CATALOG_ROLE`` (or the
``SELECT ANY DICTIONARY`` system privilege) plus ``CREATE SESSION``.
"""

from __future__ import annotations

# Packages CIS recommends revoking from PUBLIC (kept in sync with the SQL below by a test).
CIS_PUBLIC_PACKAGES = (
    "UTL_FILE",
    "UTL_HTTP",
    "UTL_TCP",
    "UTL_SMTP",
    "UTL_INADDR",
    "UTL_MAIL",
    "DBMS_ADVISOR",
    "DBMS_LOB",
    "DBMS_SQL",
    "DBMS_XMLGEN",
    "DBMS_JAVA",
    "DBMS_JOB",
    "DBMS_SCHEDULER",
    "DBMS_BACKUP_RESTORE",
    "DBMS_LDAP",
)

QUERIES: dict[str, str] = {
    "instance": """
        SELECT i.instance_name, i.host_name, i.version, i.startup_time, i.status,
               d.name AS db_name, d.log_mode, d.open_mode, d.database_role, d.cdb,
               SYS_CONTEXT('USERENV', 'CON_NAME') AS container
          FROM v$instance i CROSS JOIN v$database d""",
    "tablespaces": """
        SELECT m.tablespace_name, t.contents,
               ROUND(m.used_space * t.block_size / 1048576) AS used_mb,
               ROUND(m.tablespace_size * t.block_size / 1048576) AS max_mb,
               ROUND(m.used_percent, 1) AS used_pct
          FROM dba_tablespace_usage_metrics m
          JOIN dba_tablespaces t ON t.tablespace_name = m.tablespace_name
         ORDER BY m.used_percent DESC""",
    "invalid_objects": """
        SELECT o.owner, o.object_type, COUNT(*) AS invalid_count,
               NVL(MAX(u.oracle_maintained), 'N') AS oracle_maintained
          FROM dba_objects o LEFT JOIN dba_users u ON u.username = o.owner
         WHERE o.status = 'INVALID'
         GROUP BY o.owner, o.object_type
         ORDER BY invalid_count DESC
         FETCH FIRST 50 ROWS ONLY""",
    "session_usage": """
        SELECT (SELECT COUNT(*) FROM v$session) AS sessions,
               (SELECT COUNT(*) FROM v$session WHERE type = 'USER' AND status = 'ACTIVE') AS active_user,
               (SELECT TO_NUMBER(value) FROM v$parameter WHERE name = 'sessions') AS sessions_limit,
               (SELECT COUNT(*) FROM v$process) AS processes,
               (SELECT TO_NUMBER(value) FROM v$parameter WHERE name = 'processes') AS processes_limit
          FROM dual""",
    "blocking_sessions": """
        SELECT s.sid, s.serial# AS serial, s.username, s.blocking_session, s.event,
               ROUND(s.wait_time_micro / 1000000) AS wait_s, s.sql_id
          FROM v$session s
         WHERE s.blocking_session IS NOT NULL
         ORDER BY s.wait_time_micro DESC
         FETCH FIRST 20 ROWS ONLY""",
    "alert_log": """
        SELECT originating_timestamp, message_text
          FROM v$diag_alert_ext
         WHERE originating_timestamp > SYSTIMESTAMP - NUMTODSINTERVAL(:hours, 'HOUR')
           AND (message_text LIKE '%ORA-%' OR message_text LIKE '%TNS-%'
                OR message_text LIKE '%Checkpoint not complete%')
         ORDER BY originating_timestamp DESC
         FETCH FIRST 100 ROWS ONLY""",
    "default_passwords": """
        SELECT d.username, u.account_status
          FROM dba_users_with_defpwd d JOIN dba_users u ON u.username = d.username
         ORDER BY d.username""",
    "open_maintained_accounts": """
        SELECT username, account_status, authentication_type, last_login
          FROM dba_users
         WHERE oracle_maintained = 'Y' AND account_status = 'OPEN'
           AND authentication_type <> 'NONE'
         ORDER BY username""",
    "expiring_accounts": """
        SELECT username, account_status, expiry_date, profile
          FROM dba_users
         WHERE oracle_maintained = 'N'
           AND (account_status LIKE '%EXPIRED%' OR expiry_date < SYSDATE + :days)
         ORDER BY expiry_date NULLS LAST""",
    "dba_grantees": """
        SELECT grantee, admin_option
          FROM dba_role_privs
         WHERE granted_role = 'DBA'
           AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y'
                               UNION ALL SELECT role FROM dba_roles WHERE oracle_maintained = 'Y')
         ORDER BY grantee""",
    "powerful_privileges": """
        SELECT grantee, privilege, admin_option
          FROM dba_sys_privs
         WHERE (privilege LIKE '%ANY%'
                OR privilege IN ('BECOME USER', 'EXEMPT ACCESS POLICY', 'EXEMPT REDACTION POLICY',
                                 'ALTER SYSTEM', 'ALTER DATABASE', 'ALTER USER', 'DROP USER'))
           AND grantee NOT IN (SELECT username FROM dba_users WHERE oracle_maintained = 'Y'
                               UNION ALL SELECT role FROM dba_roles WHERE oracle_maintained = 'Y')
         ORDER BY grantee, privilege""",
    "public_execute_grants": """
        SELECT table_name AS object_name, privilege
          FROM dba_tab_privs
         WHERE grantee = 'PUBLIC' AND privilege = 'EXECUTE'
           AND table_name IN ('UTL_FILE', 'UTL_HTTP', 'UTL_TCP', 'UTL_SMTP', 'UTL_INADDR',
                              'UTL_MAIL', 'DBMS_ADVISOR', 'DBMS_LOB', 'DBMS_SQL', 'DBMS_XMLGEN',
                              'DBMS_JAVA', 'DBMS_JOB', 'DBMS_SCHEDULER', 'DBMS_BACKUP_RESTORE',
                              'DBMS_LDAP')
         ORDER BY table_name""",
    "public_sys_privs": """
        SELECT privilege FROM dba_sys_privs WHERE grantee = 'PUBLIC'
        UNION ALL
        SELECT 'ROLE ' || granted_role FROM dba_role_privs WHERE grantee = 'PUBLIC'""",
    "profile_limits": """
        SELECT profile, resource_name, limit
          FROM dba_profiles
         WHERE resource_type = 'PASSWORD'
         ORDER BY profile, resource_name""",
    "audit_settings": """
        SELECT 'unified_auditing' AS name, value FROM v$option WHERE parameter = 'Unified Auditing'
        UNION ALL
        SELECT name, value FROM v$parameter WHERE name IN ('audit_trail', 'audit_sys_operations')""",
    "audit_policies": """
        SELECT policy_name, enabled_option, entity_name, success, failure
          FROM audit_unified_enabled_policies
         ORDER BY policy_name""",
}
