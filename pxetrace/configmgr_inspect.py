from __future__ import annotations

import hashlib
import subprocess
import urllib.parse
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .audit import AuditFinding, scan_bytes
from .configmgr import (
    ConfigMgrDecryptionError,
    ConfigMgrError,
    audit_management_point,
    decrypt_media_variables,
)
from .configmgr_report import (
    endpoint,
    media_inventory,
    public_media_metadata,
    public_text,
)
from .evidence import extract_credentials, text_content
from .models import BootTarget
from .trace import Tracer

_MAX_VARIABLES_BYTES = 16 * 1024 * 1024


def _policy_text(payload: bytes) -> str:
    """Render policy bytes as readable text while retaining every byte's value."""
    return text_content(payload) or "[contenu non textuel — aucune preuve en clair]"


@dataclass(slots=True)
class ConfigMgrInspection:
    """Complete local account of the ConfigMgr control-plane checks."""

    detected: bool = False
    variables_downloaded: bool = False
    variables_decrypted: bool = False
    failure_stage: str | None = None
    variables: dict[str, object] | None = None
    variables_source: str | None = None
    variables_sha256: str | None = None
    variable_inventory: list[dict[str, object]] = field(default_factory=list)
    policy_details: list[dict[str, object]] = field(default_factory=list)
    credentials: list[dict[str, str]] = field(default_factory=list)
    policy_assignments: int = 0
    policies_downloaded: int = 0
    policy_collection_attempted: bool = False
    findings: list[AuditFinding] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)

    def as_dict(self) -> dict[str, object]:
        return {
            "detected": self.detected,
            "variables_downloaded": self.variables_downloaded,
            "variables_decrypted": self.variables_decrypted,
            "failure_stage": self.failure_stage,
            "variables": self.variables,
            "variables_source": self.variables_source,
            "variables_sha256": self.variables_sha256,
            "variable_inventory": self.variable_inventory,
            "policy_details": self.policy_details,
            "credentials": self.credentials,
            "policy_assignments": self.policy_assignments,
            "policies_downloaded": self.policies_downloaded,
            "policy_collection_attempted": self.policy_collection_attempted,
            "findings": [asdict(finding) for finding in self.findings],
            "incomplete": self.incomplete,
            "coverage_complete": self.detected and not self.incomplete,
            "scope": "ConfigMgr media variables and policies requested for Unknown Computer using the media certificate",
            "plaintext_in_report": True,
            # The operator explicitly requested a complete local audit view.
            # The generated report is still created with mode 0600.
            "secret_values_recorded": True,
        }


class ConfigMgrInspector:
    """Inspect only artifacts explicitly selected by the ConfigMgr PXE reply."""

    def __init__(
        self,
        tracer: Tracer,
        *,
        option_243: bytes | None,
        max_policies: int = 1024,
        max_policy_bytes: int = 256 * 1024 * 1024,
        max_duration: float = 300.0,
        diagnostic_directory: Path | None = None,
    ) -> None:
        self.tracer = tracer
        self.option_243 = option_243
        self.max_policies = max_policies
        self.max_policy_bytes = max_policy_bytes
        self.max_duration = max_duration
        self.diagnostic_directory = diagnostic_directory

    @staticmethod
    def _variables_target(targets: Iterable[BootTarget]) -> BootTarget | None:
        return next((target for target in targets if target.kind == "configmgr-variables"), None)

    @staticmethod
    def _read_variables(path: Path) -> bytes:
        try:
            size = path.stat().st_size
        except OSError as exc:
            raise ConfigMgrError(f"fichier de variables illisible: {exc}") from exc
        if size > _MAX_VARIABLES_BYTES:
            raise ConfigMgrError(
                f"fichier de variables supérieur à {_MAX_VARIABLES_BYTES // (1024 * 1024)} Mio"
            )
        try:
            return path.read_bytes()
        except OSError as exc:
            raise ConfigMgrError(f"fichier de variables illisible: {exc}") from exc

    def inspect(self, targets: Iterable[BootTarget], *, include_policies: bool = True) -> ConfigMgrInspection:
        result = ConfigMgrInspection()
        target = self._variables_target(targets)
        result.detected = self.option_243 is not None or target is not None
        if not result.detected:
            return result
        if self.option_243 is None:
            result.incomplete.append("option ConfigMgr 243 absente")
            return result
        if self.option_243[:1] != b"\x02":
            result.incomplete.append("média PXE protégé; mot de passe requis")
            self.tracer.emit(
                "configmgr.warning",
                "variables ConfigMgr protégées par mot de passe",
                level="warning",
            )
            return result
        result.findings.append(
            AuditFinding(
                container="ConfigMgr",
                path="DHCP option 243",
                category="média PXE sans mot de passe",
                severity="critical",
            )
        )
        if target is None or target.local_path is None or not target.local_path.is_file():
            result.incomplete.append("fichier de variables ConfigMgr non téléchargé")
            return result

        result.variables_downloaded = True
        remote_path = urllib.parse.unquote(urllib.parse.urlsplit(target.uri).path) or target.local_path.name
        result.variables_source = public_text(remote_path)
        try:
            blob = self._read_variables(target.local_path)
            result.variables_sha256 = hashlib.sha256(blob).hexdigest()
            media = decrypt_media_variables(blob, self.option_243)
        except ConfigMgrError as exc:
            if isinstance(exc, ConfigMgrDecryptionError):
                result.failure_stage = exc.stage
            result.incomplete.append(str(exc))
            self.tracer.emit(
                "configmgr.warning",
                "déchiffrement des variables ConfigMgr impossible",
                level="warning",
                path=remote_path,
                reason=str(exc),
            )
            return result

        result.variables_decrypted = True
        result.variables = public_media_metadata(media)
        result.variable_inventory = media_inventory(media)
        result.credentials.extend(item.as_dict() for item in extract_credentials(media.plaintext, source=remote_path))
        if media.pfx:
            result.findings.append(AuditFinding(
                container="ConfigMgr", path=remote_path, category="PFX média accessible",
                key="_SMSTSMediaPFX", severity="critical",
            ))
        for management_point in media.management_points:
            if management_point.lower().startswith("http://"):
                result.findings.append(
                    AuditFinding(
                        container="ConfigMgr",
                        path="variables de média",
                        category="Management Point sans TLS",
                        severity="high",
                    )
                )
        result.findings.extend(scan_bytes(media.plaintext, container=remote_path, path=remote_path))
        self.tracer.emit(
            "configmgr.variables",
            "variables de média déchiffrées et analysées en mémoire",
            management_points=len(media.management_points),
            certificate=media.pfx is not None,
        )

        if not include_policies:
            result.incomplete.append("Reprise hors ligne : stratégies non relues; couverture limitée au fichier de variables.")
            return result

        self.tracer.emit("configmgr.policies", "récupération des affectations de stratégies")
        result.policy_collection_attempted = True
        try:
            policies = audit_management_point(
                media,
                max_policies=self.max_policies,
                max_total_bytes=self.max_policy_bytes,
                max_duration=self.max_duration,
                diagnostic_directory=self.diagnostic_directory,
            )
        except (ConfigMgrError, OSError, subprocess.SubprocessError) as exc:
            result.incomplete.append(f"Management Point: {public_text(exc)}")
            self.tracer.emit(
                "configmgr.warning",
                "contrôle du Management Point incomplet",
                level="warning",
                reason=public_text(exc),
            )
            return result

        result.policy_assignments = policies.assignments
        result.policies_downloaded = sum(item.error is None for item in policies.policies)
        result.incomplete.extend(public_text(reason) for reason in policies.incomplete)
        for number, policy_item in enumerate(policies.policies, 1):
            result.policy_details.append({
                "number": number,
                "category": public_text(policy_item.category),
                "origin": endpoint(policy_item.url),
                "reference": hashlib.sha256(policy_item.url.encode()).hexdigest()[:16],
                "status": "échec" if policy_item.error else "analysée",
                "error": public_text(policy_item.error) if policy_item.error else None,
                "error_stage": policy_item.error_stage,
                "payloads": [_policy_text(payload) for payload in policy_item.payloads],
            })
            if policy_item.error:
                continue
            for nested, payload in enumerate(policy_item.payloads):
                result.credentials.extend(item.as_dict() for item in extract_credentials(
                    payload, source=f"ConfigMgr #{number} {policy_item.category} — {policy_item.url}",
                ))
                result.findings.extend(
                    scan_bytes(
                        payload,
                        container="ConfigMgr",
                        path=f"stratégie {number}/{policies.assignments}:{policy_item.category}#{nested}",
                    )
                )
        self.tracer.emit(
            "configmgr.done",
            "stratégies accessibles analysées en mémoire",
            assignments=policies.assignments,
            downloaded=result.policies_downloaded,
            failed=len(policies.incomplete),
        )
        return result
