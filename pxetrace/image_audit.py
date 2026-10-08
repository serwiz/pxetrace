"""Bounded, read-only inspection of deployment files inside downloaded images."""
from __future__ import annotations

import resource
import shutil
import subprocess
import tempfile
import time
import urllib.parse
from dataclasses import asdict, dataclass, field
from pathlib import Path, PurePosixPath
from typing import Iterable
import xml.etree.ElementTree as ET

from .evidence import inspect_credentials
from .models import BootTarget


_NAMES = {"bootstrap.ini", "customsettings.ini", "unattend.xml", "autounattend.xml",
          "sysprep.inf", "sysprep.xml", "credentials.xml", "variables.dat", "smsts.ini",
          "tsconfig.ini", "winpeshl.ini", "startnet.cmd", "setupcomplete.cmd"}
_TEXT = {".ini", ".xml", ".cfg", ".conf", ".ipxe", ".ps1", ".cmd", ".bat", ".env"}
_ARCHIVES = {".zip", ".cab", ".iso", ".7z", ".vhd", ".vhdx", ".wim", ".esd"}
_CONFIG_NAMES = _NAMES - {"startnet.cmd", "setupcomplete.cmd"}


def deployment_path(path: str) -> bool:
    normalized = path.replace("\\", "/").lower()
    parsed = PurePosixPath(normalized)
    if ".." in parsed.parts or "winsxs" in parsed.parts or any(char in path for char in "\r\n\x00"):
        return False
    if parsed.name in _NAMES:
        return True
    return parsed.suffix in _TEXT and any(part in {"deploy", "deployment", "scripts", "sms", "minint", "unattend", "panther"} for part in parsed.parts) and "winsxs" not in parsed.parts


def _bounded(command: list[str], *, limit: int = 16 * 1024**2, timeout: float = 60) -> bytes:
    def file_limit() -> None:
        resource.setrlimit(resource.RLIMIT_FSIZE, (limit + 1, limit + 1))

    # stdout is a temporary file, not a growing in-memory pipe. The child
    # cannot write an unbounded decompressed member before we check its size.
    with tempfile.TemporaryFile() as output, tempfile.TemporaryFile() as errors:
        process = subprocess.run(command, stdout=output, stderr=errors, timeout=max(0.1, timeout),
                                 check=False, preexec_fn=file_limit)
        size = output.tell()
        if size > limit:
            raise RuntimeError("fichier ou inventaire dépasse la limite de lecture")
        if process.returncode:
            raise RuntimeError("lecture du conteneur refusée, chiffrée ou format non pris en charge")
        output.seek(0)
        return output.read(limit)


@dataclass
class ImageAudit:
    scanned_files: int = 0
    wim_images: int = 0
    inventories_read: int = 0
    candidate_files: int = 0
    known_configurations: list[str] = field(default_factory=list)
    uninterpreted: list[dict[str, str]] = field(default_factory=list)
    credentials: list[dict[str, str]] = field(default_factory=list)
    findings: list[dict[str, str]] = field(default_factory=list)
    incomplete: list[str] = field(default_factory=list)
    scope: str = "fichiers de déploiement ciblés, sans montage ni exécution"

    def as_dict(self) -> dict[str, object]:
        return asdict(self)


def audit_images(targets: Iterable[BootTarget], *, max_files: int = 256,
                 max_bytes: int = 64 * 1024**2, max_seconds: float = 120) -> ImageAudit:
    result = ImageAudit()
    deadline = time.monotonic() + max_seconds
    remaining = max_bytes
    seen: set[Path] = set()

    def select_members(paths: Iterable[str]) -> list[str]:
        members = list(dict.fromkeys(path for path in paths if deployment_path(path)))
        result.candidate_files += len(members)
        for member in members:
            name = PurePosixPath(member.replace("\\", "/")).name.lower()
            if name in _CONFIG_NAMES and name not in result.known_configurations:
                result.known_configurations.append(name)
        # Read known configuration files before broad deployment-directory
        # candidates, so a script-heavy image cannot exhaust the budget first.
        return sorted(members, key=lambda path: (PurePosixPath(path.replace("\\", "/")).name.lower() not in _CONFIG_NAMES, path))

    def consume(data: bytes, source: str) -> None:
        nonlocal remaining
        remaining -= len(data)
        result.scanned_files += 1
        inspection = inspect_credentials(data, source=source)
        if inspection.limitation:
            result.uninterpreted.append({"source": source, "reason": inspection.limitation})
        items = inspection.credentials
        result.credentials.extend(item.as_dict() for item in items)
        if items:
            result.findings.append({"severity": "critical", "category": "secret dans un fichier de déploiement", "path": source})

    def allowance() -> tuple[int, float]:
        if remaining <= 0 or result.scanned_files >= max_files or time.monotonic() >= deadline:
            raise RuntimeError("limite de lecture ciblée atteinte (fichiers, volume ou durée)")
        return min(16 * 1024**2, remaining), min(60, deadline - time.monotonic())

    for target in targets:
        if target.local_path is None or target.local_path.is_symlink() or not target.local_path.is_file():
            continue
        path = target.local_path.resolve()
        if path in seen or target.kind == "configmgr-variables":
            continue
        seen.add(path)
        source = urllib.parse.unquote(urllib.parse.urlsplit(target.uri).path) or path.name
        suffix = PurePosixPath(source).suffix.lower()
        try:
            limit, timeout = allowance()
            if suffix not in _ARCHIVES:
                if suffix in _TEXT or deployment_path(source):
                    select_members([source])
                    with path.open("rb") as stream:
                        data = stream.read(limit + 1)
                    if len(data) > limit:
                        raise RuntimeError("fichier de déploiement trop volumineux")
                    consume(data, source)
                continue
            if suffix in {".wim", ".esd"}:
                executable = shutil.which("wimlib-imagex")
                if executable is None:
                    raise RuntimeError("wimlib-imagex absent : installer wimtools")
                info = ET.fromstring(_bounded([executable, "info", str(path), "--xml"], timeout=timeout))
                indexes = [node.get("INDEX", "1") for node in info.iter() if node.tag.rsplit("}", 1)[-1] == "IMAGE"]
                if not indexes:
                    raise RuntimeError("aucun index WIM lisible")
                if len(indexes) > 8:
                    result.incomplete.append(source + ": seuls les 8 premiers index WIM sont inspectés")
                for index in indexes[:8]:
                    limit, timeout = allowance()
                    listing = _bounded([executable, "dir", str(path), index], timeout=timeout).decode("utf-8", "replace")
                    members = select_members(line.strip() for line in listing.splitlines() if line.startswith(("/", "\\")))
                    result.inventories_read += 1
                    result.wim_images += 1
                    for member in members:
                        limit, timeout = allowance()
                        data = _bounded([executable, "extract", str(path), index, member, "--to-stdout", "--no-globs"], limit=limit, timeout=timeout)
                        consume(data, f"{source} / image {index} / {member.lstrip('/')}")
            else:
                executable = shutil.which("7z")
                if executable is None:
                    raise RuntimeError("7z absent : conteneur non inspecté")
                listing = _bounded([executable, "l", "-slt", "-ba", "-p-", "--", str(path)], timeout=timeout).decode("utf-8", "replace")
                members = select_members(line[7:] for line in listing.splitlines() if line.startswith("Path = "))
                result.inventories_read += 1
                for member in members:
                    limit, timeout = allowance()
                    data = _bounded([executable, "x", "-so", "-spd", "-p-", "--", str(path), member], limit=limit, timeout=timeout)
                    consume(data, source + "!/" + member)
        except (OSError, RuntimeError, subprocess.SubprocessError, ET.ParseError) as exc:
            result.incomplete.append(source + ": " + str(exc))
    return result
