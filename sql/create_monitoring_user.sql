-- Least-privilege account for oracle-health-report (run as a DBA in the target PDB).
-- Choose the password interactively; never store it in this file.
ACCEPT monitor_password CHAR PROMPT 'Password for HEALTH_MONITOR: ' HIDE
CREATE USER health_monitor IDENTIFIED BY "&monitor_password"
  DEFAULT TABLESPACE users QUOTA 0 ON users
  PROFILE DEFAULT;
GRANT CREATE SESSION TO health_monitor;
GRANT SELECT_CATALOG_ROLE TO health_monitor;
-- Three views used by the report are not covered by SELECT_CATALOG_ROLE:
GRANT SELECT ON sys.v_$diag_alert_ext TO health_monitor;
GRANT SELECT ON sys.dba_users_with_defpwd TO health_monitor;
GRANT SELECT ON sys.audit_unified_enabled_policies TO health_monitor;
