"""Private local evidence exports, with no overwrite of existing runs."""
from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

from .configmgr import _write_private
from .presentation import render_audit_screen


def save_reports(directory: Path, summary: dict[str, object]) -> None:
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    suffix = "" if not (directory / "audit-details.json").exists() and not (directory / "audit-report.txt").exists() else "-" + uuid4().hex[:10]
    details = directory / f"audit-details{suffix}.json"
    report = directory / f"audit-report{suffix}.txt"
    summary["audit_report_path"] = str(report)
    summary["audit_details_path"] = str(details)
    _write_private(details, (json.dumps(summary, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))
    _write_private(report, (render_audit_screen(summary) + "\n").encode("utf-8"))
