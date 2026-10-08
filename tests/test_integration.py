"""Integration test against a real Oracle Database (CI: gvenzl/oracle-free container).

Skipped unless OHR_INTEGRATION=1 and the ORACLE_* connection variables are set.
"""

import json
import os

import pytest

from oracle_health_report import cli

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(os.environ.get("OHR_INTEGRATION") != "1", reason="set OHR_INTEGRATION=1 to run"),
]


def test_full_report_against_real_database(capsys):
    rc = cli.main(["--format", "json", "--no-banner"])
    report = json.loads(capsys.readouterr().out)
    errors = {s["key"]: s["error"] for s in report["sections"] if s["error"]}
    assert errors == {}, f"sections not available with least privileges: {errors}"
    assert rc in (0, 1, 2)
    instance = report["sections"][0]["tables"][0]["rows"][0]
    assert instance["status"] == "OPEN"
