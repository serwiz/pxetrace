from __future__ import annotations

import io
import json
import stat
from pathlib import Path

from pxetrace.audit import AuditFinding
from pxetrace.cli import _summary_text
from pxetrace.configmgr import ConfigMgrPolicy, ConfigMgrPolicyResult, MediaVariables
from pxetrace.configmgr_inspect import ConfigMgrInspector
from pxetrace.configmgr_report import (
    media_inventory,
    public_media_metadata,
    render_configmgr_report,
    write_configmgr_report,
)
from pxetrace.models import BootTarget
from pxetrace.trace import Tracer


def _media() -> MediaVariables:
    return MediaVariables(
        plaintext=(
            '<MediaVarList><var name="SMSTSMP">http://mp.example/</var>'
            '<var name="_SMSTSSiteCode">ABC</var>'
            '<var name="_SMSTSHTTPPort">80</var>'
            '<var name="_SMSTSIISSSLState">0</var>'
            '<var name="_SMSMediaGuid">sensitive-media-identity</var>'
            '<var name="_SMSTSMediaPFX">sensitive-pfx-data</var>'
            '<var name="OSDJoinPassword">sensitive-password</var>'
            '<var name="CustomValue">unclassified-secret</var>'
            '<var name="Empty"></var></MediaVarList>'
        ).encode("utf-16le"),
        management_points=("http://mp.example/",), site_code="ABC",
        media_guid="sensitive-media-identity", pfx=b"sensitive-pfx-data",
    )


def test_inventory_displays_configuration_and_sensitive_values_for_local_audit() -> None:
    inventory = media_inventory(_media())
    by_name = {item["name"]: item for item in inventory}
    assert by_name["_SMSTSSiteCode"]["display"] == "ABC"
    assert by_name["_SMSTSHTTPPort"]["display"] == "80"
    assert by_name["SMSTSMP"]["display"] == "http://mp.example/"
    assert by_name["Empty"]["display"] == "[vide]"
    for name in ("_SMSMediaGuid", "_SMSTSMediaPFX", "OSDJoinPassword", "CustomValue"):
        assert by_name[name]["redacted"] is False
    public = json.dumps(inventory)
    for secret in ("sensitive-media-identity", "sensitive-pfx-data", "sensitive-password", "unclassified-secret"):
        assert secret in public


def test_management_point_credentials_and_query_remain_visible() -> None:
    media = _media()
    media.management_points = ("http://login:url-password@mp.example/private-path?token=query-secret",)
    media.plaintext = (
        '<MediaVarList><var name="SMSTSMP">'
        'http://login:url-password@mp.example/private-path?token=query-secret'
        '</var></MediaVarList>'
    ).encode("utf-16le")
    public = repr((media_inventory(media), public_media_metadata(media)))
    assert "http://login:url-password@mp.example/private-path?token=query-secret" in public
    for secret in ("login", "url-password", "query-secret", "private-path"):
        assert secret in public


def test_report_preserves_alerts_and_each_failed_policy(monkeypatch, tmp_path: Path) -> None:
    variables = tmp_path / "boot.var"
    variables.write_bytes(b"encrypted-placeholder")
    target = BootTarget("tftp://server/SMSTemp/boot.var", kind="configmgr-variables", local_path=variables)
    policies = [
        ConfigMgrPolicy("TaskSequence", f"http://mp.example/policy?id={number}", (), "HTTP 403 Forbidden", "téléchargement HTTP")
        for number in range(1, 9)
    ]
    incomplete = [f"stratégie #{number} (TaskSequence), téléchargement HTTP: HTTP 403 Forbidden" for number in range(1, 9)]
    monkeypatch.setattr("pxetrace.configmgr_inspect.decrypt_media_variables", lambda *_args: _media())
    monkeypatch.setattr("pxetrace.configmgr_inspect.audit_management_point", lambda *_args, **_kwargs: ConfigMgrPolicyResult(
        "http://mp.example", 8, policies, incomplete,
    ))
    result = ConfigMgrInspector(Tracer(stream=io.StringIO()), option_243=b"\x02\x00").inspect([target])
    public = result.as_dict()
    report = render_configmgr_report(public)
    console = _summary_text({"configmgr": public, "output_path": str(tmp_path)})
    assert len(result.policy_details) == 8
    assert len({item["reference"] for item in result.policy_details}) == 8
    assert public["coverage_complete"] is False
    for text in (report, console):
        assert "CRITIQUE" in text
        assert "PFX média accessible" in text
        assert "sensitive-password" in text
    assert "stratégie #8" in report
    assert "HTTP 403 Forbidden" in report
    assert "sensitive-media-identity" in report
    assert "TaskSequence × 8" in console
    assert "sensitive-media-identity" not in console
    assert "Inventaire des stratégies" not in console
    assert "Secrets éventuels non vérifiés" in console
    assert "Alertes de sécurité" in console  # Failures do not suppress findings.


def test_offline_inventory_cannot_be_mistaken_for_a_complete_policy_audit(monkeypatch, tmp_path: Path) -> None:
    variables = tmp_path / "boot.var"
    variables.write_bytes(b"encrypted-placeholder")
    target = BootTarget("tftp://server/boot.var", kind="configmgr-variables", local_path=variables)
    monkeypatch.setattr("pxetrace.configmgr_inspect.decrypt_media_variables", lambda *_args: _media())

    def unexpected_request(*_args, **_kwargs):
        raise AssertionError("No network requests allowed for an offline inventory")

    monkeypatch.setattr("pxetrace.configmgr_inspect.audit_management_point", unexpected_request)
    result = ConfigMgrInspector(Tracer(stream=io.StringIO()), option_243=b"\x02\x00").inspect([target], include_policies=False)
    assert result.variables_decrypted
    assert len(result.variable_inventory) == 9
    assert result.variables_sha256
    assert not result.as_dict()["coverage_complete"]
    assert "hors ligne" in result.incomplete[0]


def test_reports_are_private_and_do_not_overwrite_previous_run(tmp_path: Path) -> None:
    result = {"findings": [AuditFinding("ConfigMgr", "option 243", "média PXE sans mot de passe", severity="critical").as_dict()]}
    first = write_configmgr_report(tmp_path, result)
    first_contents = first.read_bytes()
    second = write_configmgr_report(tmp_path, {"incomplete": ["Échec HTTP"]})
    assert first != second
    assert first.read_bytes() == first_contents
    assert stat.S_IMODE(first.stat().st_mode) == 0o600
    assert stat.S_IMODE(second.stat().st_mode) == 0o600


def test_variable_name_cannot_inject_terminal_control_sequences() -> None:
    media = _media()
    # XML allows TAB in attributes via a character reference; output must remain one line.
    media.plaintext = b'<MediaVarList><var name="unsafe&#9;name">secret</var></MediaVarList>'.decode().encode("utf-16le")
    public = media_inventory(media)
    assert public[0]["name"] == "unsafe\\u0009name"
    assert "secret" in str(public[0]["display"])
