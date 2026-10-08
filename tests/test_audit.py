from __future__ import annotations

import shutil
import subprocess
from io import StringIO
from pathlib import Path

import pytest

from pxetrace.audit import SecurityAuditor, scan_bytes
from pxetrace.models import BootTarget
from pxetrace.trace import Tracer


def test_secret_scanner_never_returns_the_secret_value() -> None:
    secret = "DoNotPrint-This-Password"
    data = (
        "UserID=deployment-user\n"
        f"UserPassword={secret}\n"
        "PlaceholderPassword=%PASSWORD%\n"
        "<Credentials><Password><Value>encoded-value</Value></Password></Credentials>\n"
    ).encode()
    findings = scan_bytes(data, container="boot.wim", path="Bootstrap.ini")
    rendered = repr(findings)
    assert {finding.key for finding in findings} >= {
        "UserID",
        "UserPassword",
        "Password",
    }
    assert secret not in rendered
    assert "encoded-value" not in rendered
    assert "PlaceholderPassword" not in rendered


def test_secret_scanner_understands_configmgr_named_variables() -> None:
    data = b'<MediaVarList><var name="OSDJoinPassword">configmgr-secret</var></MediaVarList>'
    findings = scan_bytes(data, container="ConfigMgr", path="variables.dat")

    assert {finding.key for finding in findings} == {"OSDJoinPassword"}
    assert "configmgr-secret" not in repr(findings)


@pytest.mark.skipif(shutil.which("wimlib-imagex") is None, reason="wimlib-imagex non installé")
def test_auditor_extracts_and_scans_every_file_from_wim(tmp_path: Path) -> None:
    source = tmp_path / "source"
    bootstrap = source / "Deploy" / "Scripts" / "Bootstrap.ini"
    bootstrap.parent.mkdir(parents=True)
    bootstrap.write_text("UserID=svc-pxe\nUserPassword=TOP-SECRET-VALUE\n", encoding="utf-8")
    (source / "Windows").mkdir()
    (source / "Windows" / "harmless.bin").write_bytes(b"password=not-scanned")
    wim = tmp_path / "boot.wim"
    subprocess.run(
        ["wimlib-imagex", "capture", str(source), str(wim), "Test", "--no-acls"],
        check=True,
        capture_output=True,
    )

    output = StringIO()
    target = BootTarget("tftp://server/SMSImages/boot.wim", kind="windows-image", local_path=wim)
    result = SecurityAuditor(Tracer(compact=True, stream=output)).audit([target])

    assert result.wim_images == 1
    assert any(finding.key == "UserPassword" for finding in result.findings)
    assert "TOP-SECRET-VALUE" not in repr(result.as_dict())
    assert "TOP-SECRET-VALUE" not in output.getvalue()
    assert any("harmless.bin" in finding.path for finding in result.findings)
    assert result.incomplete == []
