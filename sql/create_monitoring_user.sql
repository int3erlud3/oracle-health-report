-- Least-privilege account for oracle-health-report (run as a DBA in the target PDB).
-- Choose the password interactively; never store it in this file.
ACCEPT monitor_password CHAR PROMPT 'Password for HEALTH_MONITOR: ' HIDE
CREATE USER health_monitor IDENTIFIED BY "&monitor_password"
  DEFAULT TABLESPACE users QUOTA 0 ON users
  PROFILE DEFAULT;
GRANT CREATE SESSION TO health_monitor;
GRANT SELECT_CATALOG_ROLE TO health_monitor;
-- SELECT_CATALOG_ROLE is not active in definer-rights code; the tool runs plain queries only.
