from __future__ import annotations

import hashlib
import os
import re
import shutil
import subprocess
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from collections.abc import Iterable
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath

from .configmgr import (
    ConfigMgrError,
    MediaVariables,
    audit_management_point,
    decrypt_media_variables,
)
from .models import BootTarget
from .trace import Tracer

_TEXT_SUFFIXES = {
    ".bat",
    ".cfg",
    ".cmd",
    ".config",
    ".dat",
    ".env",
    ".inf",
    ".ini",
    ".ipxe",
    ".json",
    ".ps1",
    ".psd1",
    ".psm1",
    ".pem",
    ".reg",
    ".rdp",
    ".txt",
    ".var",
    ".vbs",
    ".xml",
    ".yaml",
    ".yml",
}
_SCRIPT_SUFFIXES = {".bat", ".cmd", ".ps1", ".psd1", ".psm1", ".vbs"}
_SECRET_FILE_SUFFIXES = {".key", ".kdbx", ".p12", ".pfx", ".ppk"}
_ARCHIVE_SUFFIXES = {
    ".7z",
    ".bz2",
    ".cab",
    ".gz",
    ".iso",
    ".msi",
    ".msp",
    ".rar",
    ".tar",
    ".vhd",
    ".vhdx",
    ".xz",
    ".zip",
}
_EXACT_RISK_NAMES = {
    "autounattend.xml",
    "bootstrap.ini",
    "credentials.xml",
    "customsettings.ini",
    "setupcomplete.cmd",
    "smsts.ini",
    "sysprep.inf",
    "sysprep.xml",
    "tsconfig.ini",
    "unattend.xml",
    "variables.dat",
    "winpeshl.ini",
}
_RISK_PATH_MARKERS = (
    "/deploy/",
    "/minint/",
    "/panther/",
    "/scripts/",
    "/sms/",
    "/sysprep/",
    "/unattend/",
)
_KEY_PATTERN = re.compile(
    r"(?ix)^(?:"
    r"adminpassword|apikey|api_key|autologonpassword|community|connectionstring|"
    r"credential|defaultpassword|defaultusername|deployroot|domainadmin|domainadminpassword|joinaccount|joinpassword|"
    r"keymaterial|passphrase|password|passwd|privatekey|productkey|pwd|secret|token|"
    r"userdomain|userid|username|userpassword"
    r")$"
)
_IDENTITY_KEYS = {"defaultusername", "domainadmin", "joinaccount", "userdomain", "userid", "username"}
_PLACEHOLDER = re.compile(
    r"(?ix)^(?:\*+|x+|<[^>]*(?:redact|password|secret)[^>]*>|"
    r"\$\{[^}]+\}|\{\{[^}]+\}\}|%[^%]+%|none|null|n/?a|not\s+set|redacted)$"
)
_ASSIGNMENT = re.compile(
    r"(?im)^\s*[\"']?([A-Za-z][A-Za-z0-9_.-]{1,80})[\"']?\s*[:=]\s*(.*?)\s*$"
)
_XML_VALUE = re.compile(
    r"(?is)<\s*([A-Za-z][A-Za-z0-9_.:-]{1,80})\b[^>]*>([^<]{1,8192})</\s*\1\s*>"
)
_XML_NESTED_VALUE = re.compile(
    r"(?is)(?=<\s*([A-Za-z][A-Za-z0-9_.:-]{1,80})\b[^>]*>"
    r".{0,4096}?<\s*Value\b[^>]*>([^<]{1,8192})</\s*Value\s*>"
    r".{0,4096}?</\s*\1\s*>)"
)
_URL_CREDENTIAL = re.compile(r"(?i)\b(?:https?|ftp|smb)://[^\s/:@]+:([^\s/@]+)@")
_PRIVATE_KEY = re.compile(r"-----BEGIN (?:[A-Z0-9 ]+ )?PRIVATE KEY-----")
_ASCII_STRINGS = re.compile(rb"[\x20-\x7e]{4,}")
_UTF16_STRINGS = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")
_SOFTWARE_HIVE_KEYS = (
    r"\Microsoft\Windows NT\CurrentVersion\Winlogon",
    r"\Microsoft\Windows\CurrentVersion\Authentication\LogonUI",
)


@dataclass(slots=True, frozen=True)
class AuditFinding:
    container: str
    path: str
    category: str
    key: str | None = None
    severity: str = "high"

    def as_dict(self) -> dict[str, str | None]:
        return asdict(self)


@dataclass(slots=True)
class AuditResult:
    scanned_files: int = 0
    wim_images: int = 0
    findings: list[AuditFinding] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    configmgr: dict[str, object] | None = None

    def as_dict(self) -> dict[str, object]:
        return {
            "scanned_files": self.scanned_files,
            "wim_images": self.wim_images,
            "findings": [finding.as_dict() for finding in self.findings],
            "incomplete": self.incomplete,
            "coverage_complete": not self.incomplete,
            "configmgr": self.configmgr,
            "secret_values_recorded": False,
        }


def _local_name(tag: str) -> str:
    return tag.rsplit("}", 1)[-1].rsplit(":", 1)[-1]


def _has_value(value: str) -> bool:
    candidate = value.strip().strip("\"'").strip()
    return bool(candidate) and not _PLACEHOLDER.fullmatch(candidate[:512])


def _category(key: str) -> tuple[str, str]:
    normalized = key.lower().replace("-", "").replace("_", "").replace(".", "")
    if normalized in _IDENTITY_KEYS or normalized.endswith(("account", "userid", "username", "userdomain")):
        return "identifiant", "medium"
    if "productkey" in normalized:
        return "clé produit", "high"
    if any(word in normalized for word in ("token", "secret", "apikey", "privatekey", "keymaterial")):
        return "secret ou jeton", "high"
    return "mot de passe ou accès", "high"


def _sensitive_key(key: str) -> bool:
    local = _local_name(key)
    if _KEY_PATTERN.fullmatch(local):
        return True
    normalized = re.sub(r"[^a-z0-9]", "", local.lower())
    return normalized.endswith(
        (
            "apikey",
            "credential",
            "joinaccount",
            "passphrase",
            "password",
            "passwd",
            "privatekey",
            "secret",
            "token",
            "username",
        )
    )


def _decoded_views(data: bytes) -> list[str]:
    views: list[str] = []
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            views.append(data.decode("utf-16", "replace"))
        except UnicodeError:
            pass
    else:
        views.append(data.decode("utf-8", "replace"))
    # ConfigMgr variable blobs and registry exports often contain readable
    # strings inside an otherwise binary file.
    ascii_view = "\n".join(match.group().decode("ascii", "replace") for match in _ASCII_STRINGS.finditer(data))
    wide_view = "\n".join(match.group().decode("utf-16le", "replace") for match in _UTF16_STRINGS.finditer(data))
    for view in (ascii_view, wide_view):
        if view and view not in views:
            views.append(view)
    return views


def scan_bytes(data: bytes, *, container: str, path: str) -> list[AuditFinding]:
    """Find credential-shaped data without retaining or returning its value."""
    found: dict[tuple[str, str | None], AuditFinding] = {}

    def add(category: str, key: str | None, severity: str = "high") -> None:
        identity = (category, key.lower() if key else None)
        found.setdefault(identity, AuditFinding(container, path, category, key, severity))

    for text in _decoded_views(data):
        if _PRIVATE_KEY.search(text):
            add("clé privée", None, "critical")
        if _URL_CREDENTIAL.search(text):
            add("mot de passe dans une URL", None, "critical")
        for match in _ASSIGNMENT.finditer(text):
            key, value = match.groups()
            if _sensitive_key(key) and _has_value(value):
                category, severity = _category(_local_name(key))
                add(category, _local_name(key), severity)
        for match in _XML_VALUE.finditer(text):
            key, value = match.groups()
            key = _local_name(key)
            if _sensitive_key(key) and _has_value(value):
                category, severity = _category(key)
                add(category, key, severity)
        for match in _XML_NESTED_VALUE.finditer(text):
            key, value = match.groups()
            key = _local_name(key)
            if _sensitive_key(key) and _has_value(value):
                category, severity = _category(key)
                add(category, key, severity)
        try:
            root = ET.fromstring(text)
        except (ET.ParseError, ValueError):
            continue
        for element in root.iter():
            key = _local_name(str(element.tag))
            if _sensitive_key(key):
                values = [element.text or ""]
                values.extend(child.text or "" for child in element if _local_name(str(child.tag)).lower() == "value")
                if any(_has_value(value) for value in values):
                    category, severity = _category(key)
                    add(category, key, severity)
            named_key = next(
                (
                    value
                    for attribute, value in element.attrib.items()
                    if _local_name(attribute).lower() == "name"
                ),
                None,
            )
            if named_key and _sensitive_key(named_key):
                named_values = [element.text or ""]
                named_values.extend(
                    child.text or ""
                    for child in element
                    if _local_name(str(child.tag)).lower() == "value"
                )
                if any(_has_value(value) for value in named_values):
                    category, severity = _category(_local_name(named_key))
                    add(category, _local_name(named_key), severity)
            for attribute, value in element.attrib.items():
                attribute = _local_name(attribute)
                if _sensitive_key(attribute) and _has_value(value):
                    category, severity = _category(attribute)
                    add(category, attribute, severity)
    return list(found.values())


def _wim_candidate(path: str) -> tuple[int, str] | None:
    normalized = "/" + path.replace("\\", "/").lstrip("/")
    lowered = normalized.lower()
    name = PurePosixPath(lowered).name
    suffix = PurePosixPath(lowered).suffix
    if lowered.endswith("/windows/system32/config/software"):
        return 0, normalized
    if suffix in _SECRET_FILE_SUFFIXES or name in {"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}:
        return 0, normalized
    if suffix in {".env", ".pem"}:
        return 1, normalized
    if name in _EXACT_RISK_NAMES or any(word in name for word in ("credential", "password", "secret")):
        return 1, normalized
    if suffix in _SCRIPT_SUFFIXES:
        return 2, normalized
    if suffix in _TEXT_SUFFIXES and any(marker in lowered for marker in _RISK_PATH_MARKERS):
        return 3, normalized
    return None


def _wim_images(executable: str, wim: Path) -> list[int]:
    completed = subprocess.run(
        [executable, "info", str(wim), "--xml"],
        capture_output=True,
        check=False,
        timeout=120,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.decode("utf-8", "replace").strip() or "lecture des métadonnées impossible")
    try:
        root = ET.fromstring(completed.stdout)
    except ET.ParseError as exc:
        raise RuntimeError("métadonnées XML WIM invalides") from exc
    indexes = []
    for element in root.iter():
        if _local_name(str(element.tag)).upper() != "IMAGE":
            continue
        try:
            indexes.append(int(element.attrib["INDEX"]))
        except (KeyError, ValueError):
            continue
    return sorted(set(indexes)) or [1]


def _wim_paths(executable: str, wim: Path, image: int) -> tuple[list[str], int]:
    completed = subprocess.run(
        [executable, "dir", str(wim), str(image)],
        capture_output=True,
        check=False,
        text=True,
        errors="replace",
        timeout=180,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "inventaire du WIM impossible")
    ranked = [candidate for line in completed.stdout.splitlines() if (candidate := _wim_candidate(line.strip()))]
    ordered = sorted(set(ranked))
    return [path for _rank, path in ordered[:2000]], len(ordered)


def _extract_wim_candidates(executable: str, wim: Path, image: int, paths: list[str], destination: Path) -> None:
    if not paths:
        return
    env = os.environ.copy()
    env["WIMLIB_IMAGEX_IGNORE_CASE"] = "1"
    completed = subprocess.run(
        [
            executable,
            "extract",
            str(wim),
            str(image),
            "@-",
            f"--dest-dir={destination}",
            "--preserve-dir-structure",
            "--no-acls",
            "--no-attributes",
            "--no-globs",
        ],
        input="\n".join(path for path in paths if "\n" not in path) + "\n",
        capture_output=True,
        check=False,
        text=True,
        errors="replace",
        env=env,
        timeout=300,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "extraction ciblée du WIM impossible")


def _extract_wim_image(executable: str, wim: Path, image: int, destination: Path) -> None:
    completed = subprocess.run(
        [
            executable,
            "extract",
            str(wim),
            str(image),
            f"--dest-dir={destination}",
            "--no-acls",
            "--no-attributes",
            "--include-invalid-names",
        ],
        capture_output=True,
        check=False,
        text=True,
        errors="replace",
        timeout=1800,
    )
    if completed.returncode:
        raise RuntimeError(completed.stderr.strip() or "extraction intégrale du WIM impossible")


def _scan_file(path: Path, *, container: str, display_path: str) -> list[AuditFinding]:
    if path.is_symlink() or not path.is_file():
        return []
    suffix = path.suffix.lower()
    name = path.name.lower()
    if suffix in _SECRET_FILE_SUFFIXES or name in {"id_dsa", "id_ecdsa", "id_ed25519", "id_rsa"}:
        return [AuditFinding(container, display_path, "fichier de clé ou coffre", None, "critical")]
    findings: dict[tuple[str, str | None], AuditFinding] = {}
    overlap = b""
    with path.open("rb") as stream:
        while chunk := stream.read(4 * 1024 * 1024):
            for finding in scan_bytes(overlap + chunk, container=container, path=display_path):
                findings.setdefault((finding.category, finding.key), finding)
            overlap = chunk[-64 * 1024 :]
    return list(findings.values())


def _scan_software_hive(path: Path, *, container: str, display_path: str) -> list[AuditFinding] | None:
    executable = shutil.which("hivexregedit")
    if executable is None:
        return None
    findings: list[AuditFinding] = []
    for key in _SOFTWARE_HIVE_KEYS:
        completed = subprocess.run(
            [
                executable,
                "--export",
                "--unsafe-printable-strings",
                "--prefix",
                r"HKEY_LOCAL_MACHINE\SOFTWARE",
                str(path),
                key,
            ],
            capture_output=True,
            check=False,
            timeout=60,
        )
        if completed.returncode == 0:
            findings.extend(scan_bytes(completed.stdout, container=container, path=display_path))
    return findings


def _scan_registry_hive(path: Path, *, container: str, display_path: str) -> list[AuditFinding] | None:
    executable = shutil.which("hivexregedit")
    if executable is None:
        return None
    completed = subprocess.run(
        [executable, "--export", "--unsafe-printable-strings", str(path), "\\"],
        capture_output=True,
        check=False,
        timeout=300,
    )
    if completed.returncode:
        raise RuntimeError("export complet de la ruche impossible")
    return scan_bytes(completed.stdout, container=container, path=display_path)


class SecurityAuditor:
    def __init__(self, tracer: Tracer, *, configmgr_option_243: bytes | None = None) -> None:
        self.tracer = tracer
        self.configmgr_option_243 = configmgr_option_243
        self.media_variables: MediaVariables | None = None
        self._archive_hashes: set[str] = set()
        self._archive_expanded_bytes = 0
        self._archive_expanded_files = 0

    def audit(self, targets: Iterable[BootTarget], *, include_configmgr: bool = True) -> AuditResult:
        result = AuditResult()
        downloaded = [target for target in targets if target.local_path and target.local_path.is_file()]
        self.tracer.emit("audit.start", "analyse des fichiers à risque", files=len(downloaded))
        seen: set[Path] = set()
        for target in downloaded:
            assert target.local_path is not None
            local = target.local_path.resolve()
            if local in seen:
                continue
            seen.add(local)
            remote_path = urllib.parse.unquote(urllib.parse.urlsplit(target.uri).path) or local.name
            if target.kind == "windows-image" or remote_path.lower().endswith(".wim"):
                self._audit_wim(local, remote_path, result)
                continue
            if target.kind == "configmgr-variables":
                if include_configmgr:
                    self._audit_configmgr_variables(local, remote_path, result)
                continue
            try:
                findings = _scan_file(local, container=remote_path, display_path=remote_path)
            except OSError as exc:
                result.incomplete.append(f"{remote_path}: {exc}")
                self.tracer.emit("audit.warning", "fichier illisible", level="warning", path=remote_path)
                continue
            result.scanned_files += 1
            self._record(findings, result)
            if local.suffix.lower() in _ARCHIVE_SUFFIXES:
                self._audit_archive(
                    local,
                    container=remote_path,
                    display_path=remote_path,
                    result=result,
                    depth=1,
                )
        if self.media_variables is not None:
            self._audit_management_point(result)
        if result.scanned_files == 0 and result.wim_images == 0 and not result.incomplete:
            result.incomplete.append("aucun fichier de configuration ou WIM analysable")
            self.tracer.emit(
                "audit.warning",
                "aucun fichier de configuration ou WIM n'a pu être analysé",
                level="warning",
            )
        if not result.findings and not result.incomplete:
            self.tracer.emit("audit.clean", "aucune exposition détectée", files=result.scanned_files)
        elif result.findings:
            self.tracer.emit(
                "audit.done",
                "analyse terminée; les valeurs restent masquées",
                findings=len(result.findings),
                files=result.scanned_files,
            )
        return result

    def _audit_management_point(self, result: AuditResult) -> None:
        assert self.media_variables is not None
        self.tracer.emit("configmgr.policies", "récupération des affectations de stratégies")
        try:
            policies = audit_management_point(self.media_variables)
        except (ConfigMgrError, OSError, subprocess.SubprocessError) as exc:
            result.incomplete.append(f"ConfigMgr Management Point: {exc}")
            self.tracer.emit(
                "configmgr.warning",
                "audit du Management Point incomplet",
                level="warning",
                reason=str(exc),
            )
            return
        if result.configmgr is None:
            result.configmgr = {}
        result.configmgr.update(
            {
                "management_point": policies.management_point,
                "policy_assignments": policies.assignments,
                "policies_downloaded": sum(policy.error is None for policy in policies.policies),
                "policy_plaintext_persisted": False,
            }
        )
        result.incomplete.extend(f"ConfigMgr {message}" for message in policies.incomplete)
        for number, policy_item in enumerate(policies.policies, 1):
            if policy_item.error:
                continue
            for nested, payload in enumerate(policy_item.payloads):
                self._record(
                    scan_bytes(
                        payload,
                        container="ConfigMgr",
                        path=f"stratégie {number}/{policies.assignments}:{policy_item.category}#{nested}",
                    ),
                    result,
                )
                result.scanned_files += 1
        self.tracer.emit(
            "configmgr.done",
            "stratégies accessibles analysées en mémoire",
            assignments=policies.assignments,
            downloaded=sum(policy.error is None for policy in policies.policies),
            failed=len(policies.incomplete),
        )

    def _audit_configmgr_variables(self, path: Path, remote_path: str, result: AuditResult) -> None:
        if self.configmgr_option_243 is None:
            result.incomplete.append(f"{remote_path}: option ConfigMgr 243 absente")
            return
        if self.configmgr_option_243[:1] != b"\x02":
            result.incomplete.append(
                f"{remote_path}: média PXE protégé; contenu inaccessible sans son mot de passe"
            )
            self.tracer.emit(
                "audit.warning",
                "variables ConfigMgr protégées par mot de passe",
                level="warning",
                path=remote_path,
            )
            return
        try:
            media = decrypt_media_variables(path.read_bytes(), self.configmgr_option_243)
        except (OSError, ConfigMgrError) as exc:
            result.incomplete.append(f"{remote_path}: {exc}")
            self.tracer.emit(
                "audit.warning",
                "déchiffrement des variables ConfigMgr impossible",
                level="warning",
                path=remote_path,
                reason=str(exc),
            )
            return
        self.media_variables = media
        result.configmgr = media.public_dict()
        result.scanned_files += 1
        self._record(scan_bytes(media.plaintext, container=remote_path, path=remote_path), result)
        self.tracer.emit(
            "configmgr.variables",
            "variables de média déchiffrées et analysées en mémoire",
            management_points=len(media.management_points),
            certificate=media.pfx is not None,
        )

    def _audit_wim(self, wim: Path, remote_path: str, result: AuditResult) -> None:
        executable = shutil.which("wimlib-imagex")
        if executable is None:
            message = f"{remote_path}: wimlib-imagex absent"
            result.incomplete.append(message)
            self.tracer.emit(
                "audit.warning",
                "WIM téléchargé mais contenu non analysé: installez wimtools",
                level="warning",
                path=remote_path,
            )
            return
        self.tracer.emit("audit.wim", "inspection du WIM", path=remote_path)
        try:
            verified = subprocess.run(
                [executable, "verify", str(wim)],
                capture_output=True,
                check=False,
                text=True,
                errors="replace",
                timeout=600,
            )
            if verified.returncode:
                raise RuntimeError(verified.stderr.strip() or "intégrité WIM invalide")
            images = _wim_images(executable, wim)
            for image in images:
                with tempfile.TemporaryDirectory(prefix="pxetrace-audit-") as temporary:
                    destination = Path(temporary)
                    _extract_wim_image(executable, wim, image, destination)
                    scanned = 0
                    for extracted in destination.rglob("*"):
                        if extracted.is_symlink() or not extracted.is_file():
                            continue
                        relative = "/" + extracted.relative_to(destination).as_posix()
                        try:
                            findings = _scan_file(
                                extracted,
                                container=remote_path,
                                display_path=f"image {image}:{relative}",
                            )
                        except OSError:
                            result.incomplete.append(f"{remote_path}: image {image}:{relative} illisible")
                            continue
                        try:
                            with extracted.open("rb") as stream:
                                is_hive = stream.read(4) == b"regf"
                            if is_hive:
                                hive_findings = _scan_registry_hive(
                                    extracted,
                                    container=remote_path,
                                    display_path=f"image {image}:{relative}",
                                )
                                if hive_findings is None:
                                    message = f"{remote_path}: ruche {relative} non analysée (hivexregedit absent)"
                                    if message not in result.incomplete:
                                        result.incomplete.append(message)
                                else:
                                    findings.extend(hive_findings)
                        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
                            result.incomplete.append(f"{remote_path}: ruche {relative}: {exc}")
                        scanned += 1
                        self._record(findings, result)
                        if extracted.suffix.lower() in _ARCHIVE_SUFFIXES:
                            self._audit_archive(
                                extracted,
                                container=remote_path,
                                display_path=f"image {image}:{relative}",
                                result=result,
                                depth=1,
                            )
                    result.scanned_files += scanned
                    result.wim_images += 1
                    self.tracer.emit(
                        "audit.wim-image",
                        "image WIM inspectée",
                        image=image,
                        files=scanned,
                        exhaustive=True,
                    )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            result.incomplete.append(f"{remote_path}: {exc}")
            self.tracer.emit(
                "audit.warning",
                "analyse du WIM incomplète",
                level="warning",
                path=remote_path,
                reason=str(exc),
            )

    def _audit_archive(
        self,
        archive: Path,
        *,
        container: str,
        display_path: str,
        result: AuditResult,
        depth: int,
    ) -> None:
        if depth > 6:
            result.incomplete.append(f"{container}: profondeur d'archive dépassée dans {display_path}")
            return
        executable = shutil.which("7z")
        if executable is None:
            result.incomplete.append(f"{container}: archive non extraite (7z absent): {display_path}")
            return
        try:
            digest = hashlib.sha256()
            with archive.open("rb") as stream:
                while chunk := stream.read(1024 * 1024):
                    digest.update(chunk)
            identity = digest.hexdigest()
            if identity in self._archive_hashes:
                return
            self._archive_hashes.add(identity)
            with tempfile.TemporaryDirectory(prefix="pxetrace-archive-") as temporary:
                destination = Path(temporary)
                completed = subprocess.run(
                    [executable, "x", "-y", "-p-", f"-o{destination}", str(archive)],
                    capture_output=True,
                    check=False,
                    text=True,
                    errors="replace",
                    timeout=600,
                )
                if completed.returncode:
                    raise RuntimeError("archive chiffrée, corrompue ou format non pris en charge")
                for nested in destination.rglob("*"):
                    if nested.is_symlink() or not nested.is_file():
                        continue
                    size = nested.stat().st_size
                    self._archive_expanded_files += 1
                    self._archive_expanded_bytes += size
                    if self._archive_expanded_files > 100_000 or self._archive_expanded_bytes > 8 * 1024**3:
                        raise RuntimeError("limite anti-bombe d'archive atteinte")
                    relative = nested.relative_to(destination).as_posix()
                    nested_display = f"{display_path}!/{relative}"
                    self._record(
                        _scan_file(nested, container=container, display_path=nested_display),
                        result,
                    )
                    result.scanned_files += 1
                    if nested.suffix.lower() in _ARCHIVE_SUFFIXES:
                        self._audit_archive(
                            nested,
                            container=container,
                            display_path=nested_display,
                            result=result,
                            depth=depth + 1,
                        )
        except (OSError, RuntimeError, subprocess.SubprocessError) as exc:
            result.incomplete.append(f"{container}: {display_path}: {exc}")
            self.tracer.emit(
                "audit.warning",
                "conteneur imbriqué non analysé intégralement",
                level="warning",
                path=display_path,
                reason=str(exc),
            )

    def _record(self, findings: Iterable[AuditFinding], result: AuditResult) -> None:
        existing = {(item.container, item.path, item.category, item.key) for item in result.findings}
        for finding in findings:
            identity = (finding.container, finding.path, finding.category, finding.key)
            if identity in existing:
                continue
            existing.add(identity)
            result.findings.append(finding)
            self.tracer.emit(
                "audit.finding",
                finding.category,
                level="warning",
                path=finding.path,
                key=finding.key,
                severity=finding.severity,
            )
