# Security Policy

## Reporting a vulnerability

Please do **not** open a public issue for security problems. Use GitHub's
[private vulnerability reporting](../../security/advisories/new) for this repository
instead. You can expect an initial response within 7 days.

## Security review notes

- Read-only: only the fixed `SELECT` statements in `queries.py` are executed, guarded
  at runtime, inside a `SET TRANSACTION READ ONLY` transaction, with bind variables.
- Credentials are accepted only from the environment, a password file that must not be
  group/world-accessible, or a wallet – never from command-line arguments. The password
  is excluded from `repr()` and never written to reports or logs.
- HTML output is rendered with Jinja2 autoescaping and a restrictive CSP; output files
  are created with mode 0600 and `O_NOFOLLOW`.
- CI runs ruff (incl. flake8-bandit rules), Bandit, pip-audit and a gitleaks secret
  scan on every push and pull request; GitHub Actions are pinned to commit SHAs and
  run with `contents: read` only. The integration job uses random, masked, throw-away
  passwords for a local container.
