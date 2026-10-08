from __future__ import annotations

from pathlib import Path

from pxetrace.configmgr import (
    ConfigMgrDecryptionError,
    ConfigMgrPolicy,
    ConfigMgrPolicyResult,
    MediaVariables,
)
from pxetrace.configmgr_inspect import ConfigMgrInspector
from pxetrace.models import BootTarget
from pxetrace.trace import Tracer


def test_targeted_configmgr_inspector_ignores_wim_files(tmp_path: Path) -> None:
    wim = tmp_path / "boot.wim"
    wim.write_bytes(b"not a real WIM")
    target = BootTarget("tftp://server/SMSImages/boot.wim", kind="windows-image", local_path=wim)

    result = ConfigMgrInspector(Tracer(), option_243=None).inspect([target])

    assert result.detected is False
    assert result.incomplete == []
    assert result.findings == []


def test_configmgr_inspector_reports_missing_variables_download() -> None:
    result = ConfigMgrInspector(Tracer(), option_243=b"\x02\x00").inspect([])

    assert result.detected is True
    assert result.variables_downloaded is False
    assert result.incomplete == ["fichier de variables ConfigMgr non téléchargé"]


def test_configmgr_inspector_reports_full_local_audit_metadata(monkeypatch, tmp_path: Path) -> None:
    variables = tmp_path / "client.boot.var"
    variables.write_bytes(b"encrypted-placeholder")
    target = BootTarget(
        "tftp://server/SMSTemp/client.boot.var",
        kind="configmgr-variables",
        local_path=variables,
    )
    media = MediaVariables(
        plaintext=(
            '<MediaVarList><var name="OSDJoinPassword">do-not-record-me</var></MediaVarList>'
        ).encode("utf-16le"),
        management_points=("https://mp.example",),
        site_code="ABC",
        media_guid="GUID",
        pfx=b"pfx",
    )
    policies = ConfigMgrPolicyResult(
        "https://mp.example",
        1,
        [
            ConfigMgrPolicy(
                "TaskSequence",
                "https://mp.example/policy",
                (b'<sequence><variable name="ApiToken">also-secret</variable></sequence>',),
            )
        ],
        [],
    )
    monkeypatch.setattr("pxetrace.configmgr_inspect.decrypt_media_variables", lambda *_args: media)
    monkeypatch.setattr("pxetrace.configmgr_inspect.audit_management_point", lambda *_args, **_kwargs: policies)

    result = ConfigMgrInspector(Tracer(), option_243=b"\x02\x00").inspect([target])
    public = repr(result.as_dict())

    assert result.variables_decrypted is True
    assert result.policy_assignments == 1
    assert result.policies_downloaded == 1
    assert {finding.key for finding in result.findings} >= {"OSDJoinPassword", "ApiToken"}
    assert "do-not-record-me" in public
    assert "also-secret" in public


def test_invalid_session_key_stops_before_management_point(monkeypatch, tmp_path: Path) -> None:
    variables = tmp_path / "client.boot.var"
    variables.write_bytes(b"encrypted-placeholder")
    target = BootTarget(
        "tftp://server/SMSTemp/client.boot.var", kind="configmgr-variables", local_path=variables,
    )

    def fail_decryption(*_args):
        raise ConfigMgrDecryptionError("clé non récupérée", stage="session-key-decryption")

    def unexpected_management_point(*_args, **_kwargs):
        raise AssertionError("Le Management Point ne doit pas être contacté sans clé valide")

    monkeypatch.setattr("pxetrace.configmgr_inspect.decrypt_media_variables", fail_decryption)
    monkeypatch.setattr("pxetrace.configmgr_inspect.audit_management_point", unexpected_management_point)
    result = ConfigMgrInspector(Tracer(), option_243=b"\x02\x00").inspect([target])
    assert result.as_dict()["failure_stage"] == "session-key-decryption"
    assert result.variables_decrypted is False
    assert result.as_dict()["coverage_complete"] is False
    assert result.incomplete == ["clé non récupérée"]
