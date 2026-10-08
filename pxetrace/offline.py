"""Replay locally saved evidence. This module never performs network requests."""
from __future__ import annotations

import json
import re
import tempfile
import urllib.parse
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any

from .configmgr import ConfigMgrError, _decrypt_cms, _extract_pfx, expand_policy_payload
from .evidence import extract_credentials
from .image_audit import audit_images
from .models import BootTarget


def _read(path: Path, limit: int = 64 * 1024**2) -> str:
    with path.open("rb") as stream:
        data = stream.read(limit + 1)
    if len(data) > limit:
        raise ValueError("rapport local trop volumineux")
    return data.decode("utf-8")


def _legacy_report(path: Path) -> dict[str, Any]:
    text = _read(path)
    config: dict[str, Any] = {"credentials": [], "findings": [], "incomplete": [], "variable_inventory": [], "policy_details": [], "variables_decrypted": "Variables : déchiffrées" in text}
    count = re.search(r"Stratégies analysées : (\d+)/(\d+)", text)
    if count:
        config["policies_downloaded"], config["policy_assignments"] = map(int, count.groups())
    variable_part = text.split("Variables du .boot.var", 1)[-1].split("Alertes de sécurité", 1)[0]
    for match in re.finditer(r"(?m)^\s*(?:│ valeur : )?([\w]+) = (.*)$", variable_part):
        config["variable_inventory"].append({"name": match[1], "display": match[2]})
    for match in re.finditer(r"(?m)^  \[(CRITIQUE|ÉLEVÉ|MOYEN)\] (.+?) (?:—.*? )?\(\d+\)$", text):
        config["findings"].append({"severity": {"CRITIQUE": "critical", "ÉLEVÉ": "high", "MOYEN": "medium"}[match[1]], "category": match[2], "path": "ancien rapport"})
    config["incomplete"] = re.findall(r"(?m)^  - (.*)$", text)
    policy: dict[str, Any] | None = None
    for line in text.splitlines():
        policy_match = re.match(r"  #(\d+) \[([^]]+)\] (.*?) — référence (.*?); origine (.*)", line)
        if policy_match:
            policy = {"number": int(policy_match[1]), "status": policy_match[2], "category": policy_match[3], "reference": policy_match[4], "origin": policy_match[5], "payloads": [], "error": None if policy_match[2] == "analysée" else "CMS non décodé dans la capture"}
            config["policy_details"].append(policy)
        elif policy is not None and line.lstrip().startswith("<"):
            # Undo only the historical escapes for XML whitespace, not any
            # arbitrary escape supplied by the captured server.
            payload = line.replace("\\u000d", "\r").replace("\\u000a", "\n").replace("\\u0009", "\t")
            policy["payloads"].append(payload)
    config["incomplete"].append("Relecture d'un ancien rapport : les réponses CMS brutes n'y sont pas conservées.")
    return config


def inspect_capture(directory: Path) -> dict[str, Any]:
    directory = directory.resolve()
    if not directory.is_dir():
        raise ValueError("--offline attend un dossier de capture")
    summary: dict[str, Any] = {"offline": True, "output_path": str(directory)}
    details = directory / "audit-details.json"
    legacy = directory / "configmgr-report.txt"
    if details.is_file() and not details.is_symlink():
        loaded = json.loads(_read(details))
        if not isinstance(loaded, dict):
            raise ValueError("rapport JSON invalide")
        summary.update(loaded)
    elif legacy.is_file() and not legacy.is_symlink():
        summary["configmgr"] = _legacy_report(legacy)
    summary["offline"] = True
    config = summary.get("configmgr", {})
    variables = {item["name"]: item["display"] for item in config.get("variable_inventory", [])}
    root = ET.Element("MediaVarList")
    for name, value in variables.items():
        ET.SubElement(root, "var", name=name).text = value
    credentials = [item.as_dict() for item in extract_credentials(ET.tostring(root), source=".boot.var (capture locale)")]
    media_mp = variables.get("SMSTSMP") or variables.get("_SMSTSMP")
    if media_mp and "boot" not in summary:
        summary["boot"] = {"effective_boot_server": urllib.parse.urlsplit(media_mp).hostname}
    with tempfile.TemporaryDirectory(prefix="pxetrace-replay-") as temporary:
        certificate = key = None
        if variables.get("_SMSTSMediaPFX") and variables.get("_SMSMediaGuid"):
            try:
                certificate, key = _extract_pfx(bytes.fromhex(variables["_SMSTSMediaPFX"]), variables["_SMSMediaGuid"][:31], Path(temporary))
            except (ValueError, ConfigMgrError):
                config.setdefault("incomplete", []).append("PFX de la capture non exploitable pour la relecture CMS")
        for item in config.get("policy_details", []):
            if item.get("error") and certificate and key:
                match = re.search(r"\[capture locale: (policy-\d+-[a-f0-9]+\.bin)\]", item["error"])
                if match:
                    saved = directory / "configmgr-diagnostics" / match[1]
                    if saved.is_file() and not saved.is_symlink() and saved.resolve().is_relative_to(directory):
                        try:
                            with saved.open("rb") as stream:
                                raw = stream.read(64 * 1024**2 + 1)
                            if len(raw) > 64 * 1024**2:
                                raise ConfigMgrError("capture CMS trop volumineuse")
                            item["payloads"] = [_decrypt_cms(raw, certificate, key).decode("utf-8")]
                            item["error"] = None
                            item["status"] = "analysée"
                            prefix = f"stratégie #{item['number']} "
                            config["incomplete"] = [reason for reason in config.get("incomplete", []) if not reason.startswith(prefix)]
                        except ConfigMgrError as exc:
                            item["error"] = str(exc)
            for payload in item.get("payloads", []):
                try:
                    expanded = expand_policy_payload(payload.encode("utf-8"), max_total_bytes=16 * 1024**2)
                except ConfigMgrError as exc:
                    config.setdefault("incomplete", []).append(f"stratégie #{item['number']}: {exc}")
                    item["error"] = str(exc)
                    item["status"] = "échec"
                    continue
                for data in expanded:
                    credentials.extend(evidence.as_dict() for evidence in extract_credentials(data, source=f"ConfigMgr #{item['number']} {item['category']} (capture locale)"))
    if config:
        config["credentials"] = credentials
        config["coverage_complete"] = False
        config["policies_downloaded"] = sum(not item.get("error") for item in config.get("policy_details", []))
        summary["configmgr"] = config
    targets = []
    # Only captured object trees or explicit text fixtures; never follow a path
    # from JSON back outside the directory selected by the operator.
    for path in directory.rglob("*"):
        if path.is_symlink() or not path.is_file() or not path.resolve().is_relative_to(directory):
            continue
        relative = path.relative_to(directory)
        if relative.parts[0] not in {"tftp", "http", "https", "fixtures"}:
            continue
        name = re.sub(r"\.[0-9a-f]{10}$", "", relative.as_posix())
        targets.append(BootTarget("file:///" + name, local_path=path))
    summary["image_audit"] = audit_images(targets).as_dict()
    return summary
