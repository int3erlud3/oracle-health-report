"""Render the report as JSON, plain text or a self-contained HTML page."""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any

from jinja2 import Environment, PackageLoader

from . import __version__
from .checks import RANK, Section, worst

CSS = """
body{font-family:system-ui,-apple-system,Segoe UI,Roboto,sans-serif;margin:2rem;
color:#1d2430;background:#f6f8fa}
h1{margin-bottom:.2rem}.meta{color:#57606a;margin-bottom:1.5rem}
section{background:#fff;border:1px solid #d0d7de;border-radius:8px;padding:1rem 1.25rem;margin-bottom:1rem}
h2{font-size:1.1rem;display:flex;gap:.6rem;align-items:center}
.badge{font-size:.75rem;font-weight:700;padding:.15rem .5rem;border-radius:999px;color:#fff}
.OK{background:#1a7f37}.WARNING{background:#9a6700}.CRITICAL{background:#cf222e}.UNKNOWN{background:#6e7781}
ul.findings{padding-left:1.2rem}li.CRITICAL{color:#cf222e}li.WARNING{color:#9a6700}
li.CRITICAL,li.WARNING{background:none}
table{border-collapse:collapse;width:100%;font-size:.85rem;margin:.5rem 0 1rem}
th,td{border:1px solid #d0d7de;padding:.3rem .5rem;text-align:left;vertical-align:top}
th{background:#f6f8fa}td{word-break:break-word}h3{font-size:.95rem;margin:.8rem 0 .2rem}
.empty{color:#57606a;font-style:italic}footer{color:#57606a;font-size:.8rem;margin-top:2rem}
""".strip()


def _jsonable(value: Any) -> Any:
    if isinstance(value, datetime | date):
        return value.isoformat()
    if isinstance(value, Decimal):
        return float(value)
    if isinstance(value, bytes):
        return value.hex()
    return value


@dataclass
class Report:
    sections: list[Section]
    target: str = ""
    generated_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    @property
    def status(self) -> str:
        return worst([s.status for s in self.sections])

    @property
    def exit_code(self) -> int:
        return RANK[self.status]

    def to_dict(self) -> dict:
        return {
            "tool": "oracle-health-report",
            "version": __version__,
            "generated_at": self.generated_at.isoformat(timespec="seconds"),
            "target": self.target,
            "status": self.status,
            "exit_code": self.exit_code,
            "sections": [
                {
                    "key": s.key,
                    "title": s.title,
                    "status": s.status,
                    "error": s.error,
                    "findings": [{"severity": f.severity, "message": f.message} for f in s.findings],
                    "tables": [
                        {"title": t.title, "rows": [{k: _jsonable(v) for k, v in r.items()} for r in t.rows]}
                        for t in s.tables
                    ],
                }
                for s in self.sections
            ],
        }


def render_text(report: Report) -> str:
    lines = [f"Oracle health report for {report.target}  -  {report.generated_at:%Y-%m-%d %H:%M} UTC", ""]
    for s in report.sections:
        lines.append(f"[{s.status:<8}] {s.title}")
        if s.error:
            lines.append(f"           error: {s.error}")
        lines.extend(f"           - {f.severity}: {f.message}" for f in s.findings)
    lines += ["", f"OVERALL: {report.status}"]
    return "\n".join(lines)


def render_html(report: Report) -> str:
    # autoescape=True: every value (object names, alert log text, ...) is HTML-escaped.
    env = Environment(loader=PackageLoader("oracle_health_report", "templates"), autoescape=True)
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode()
    data = report.to_dict()
    return env.get_template("report.html.j2").render(report=data, css=CSS, css_hash=css_hash)
