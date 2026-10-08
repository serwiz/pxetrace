"""Human-readable ConfigMgr evidence for an explicitly authorized local audit."""

from __future__ import annotations

import hashlib
import re
import xml.etree.ElementTree as ET
from collections import Counter
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from .configmgr import MediaVariables, _write_private


_CONFIG_FIELDS = {
    "_smstsbootmediapackageid": (r"[A-Za-z0-9]{8}", "Package de l'image de démarrage"),
    "_smstssitecode": (r"[A-Za-z0-9]{3}", "Code du site ConfigMgr"),
    "_smstshttpport": (r"[0-9]{1,5}", "Port HTTP annoncé"),
    "_smstshttpsport": (r"[0-9]{1,5}", "Port HTTPS annoncé"),
    "_smstsiissslstate": (r"[0-9]{1,10}", "État SSL annoncé; ne prouve pas à lui seul la protection des flux"),
    "_smstslaunchmode": (r"[A-Za-z]{1,24}", "Mode de lancement"),
    "_smstspreferredmpenabled": (r"(?i:0|1|true|false)", "Préférence de Management Point"),
    "_smstsusefirstcert": (r"(?i:0|1|true|false)", "Sélection du premier certificat"),
}
_GUID = r"\{?[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}\}?"
_GUID_FIELDS = {f"_smsts{arch}unknownmachineguid" for arch in ("x64", "x86", "arm64")}
_MP_FIELDS = {"smstsmp", "_smstsmp", "smstslocationmps", "_smstslocationmps"}
_PUBLIC_BINARY = {"_smstspublicrootkey", "_smstssitesigningcertificate"}
_URL = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def _paint(value: object, code: str, enabled: bool) -> str:
    text = str(value)
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def endpoint(value: str) -> str:
    """Return a complete endpoint for a local audit, including URL details."""
    return value


def public_text(value: object) -> str:
    """Make arbitrary captured text safe for a terminal without hiding its value."""
    text = str(value)
    return "".join(char if char.isprintable() else f"\\u{ord(char):04x}" for char in text)


def media_inventory(media: MediaVariables) -> list[dict[str, object]]:
    root = ET.fromstring(media.plaintext.decode("utf-16le"))
    inventory: list[dict[str, object]] = []
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].casefold() != "var" or not element.get("name"):
            continue
        name = element.attrib["name"]
        folded = name.casefold()
        value = (element.text or "").strip()
        hidden = False
        display = public_text(value)
        note = "Valeur complète extraite du .boot.var"
        if not value:
            display, note, hidden = "[vide]", "Aucune valeur", False
        elif folded in {"_smsmediaguid", "_smstsmediapfx"}:
            note = "Valeur complète extraite du .boot.var; matériel d'authentification"
        elif folded in _PUBLIC_BINARY:
            if re.fullmatch(r"(?:[0-9a-fA-F]{2})+", value):
                binary = bytes.fromhex(value)
                display = public_text(value)
                note = f"Valeur hexadécimale complète; {len(binary)} octets; SHA-256 {hashlib.sha256(binary).hexdigest()}"
        elif folded in _MP_FIELDS:
            addresses = [endpoint(match.group()) for match in _URL.finditer(value)]
            if addresses:
                display = public_text(value)
                note = "Valeur complète du Management Point"
        elif folded in _GUID_FIELDS and re.fullmatch(_GUID, value):
            display, note = public_text(value), "Identité Unknown Computer annoncée"
        elif folded in _CONFIG_FIELDS:
            pattern, description = _CONFIG_FIELDS[folded]
            if re.fullmatch(pattern, value):
                display, note = public_text(value), description
        inventory.append({
            "name": public_text(name), "display": display, "redacted": hidden,
            "characters": len(value), "description": note,
        })
    return inventory


def public_media_metadata(media: MediaVariables) -> dict[str, object]:
    result = media.public_dict()
    result.pop("plaintext_persisted", None)
    result["plaintext_in_report"] = True
    result["management_points"] = list(media.management_points)
    result["media_guid"] = media.media_guid
    result["pfx_hex"] = media.pfx.hex() if media.pfx else None
    return result


def finding_guidance(category: str) -> str:
    if category == "média PXE sans mot de passe":
        return "Exiger un mot de passe PXE et limiter l'accès aux segments réseau autorisés."
    if category == "PFX média accessible":
        return "Revoir l'accès au média et aux stratégies; évaluer le renouvellement du certificat si exposé."
    if category == "Management Point sans TLS":
        return "Vérifier la protection des échanges avec ce MP; cette URL ne décrit pas toute la configuration HTTPS/HTTP amélioré."
    if category == "identifiant":
        return "Vérifier le besoin et les droits du compte; sa présence seule ne prouve pas un mot de passe exposé."
    return "Vérifier ce champ dans la stratégie source; retirer les secrets inutiles et limiter les droits associés."


def render_configmgr_report(
    result: dict[str, object], *, detailed: bool = True, color: bool = False
) -> str:
    variables = result.get("variable_inventory")
    variables = variables if isinstance(variables, list) else []
    findings = result.get("findings")
    findings = findings if isinstance(findings, list) else []
    incomplete = result.get("incomplete")
    incomplete = incomplete if isinstance(incomplete, list) else []
    coverage = "complète sur le périmètre ci-dessous" if result.get("coverage_complete") else "incomplète"
    variable_state = "déchiffrées" if result.get("variables_decrypted") else "non déchiffrées"
    lines = [
        _paint("Contrôle de sécurité ConfigMgr", "1;36", color),
        f"  Couverture : {_paint(coverage, '1;32' if coverage.startswith('complète') else '1;33', color)}",
        f"  Alertes : {_paint(len(findings), '1;31' if findings else '1;32', color)}; "
        f"limites/erreurs : {_paint(len(incomplete), '1;33' if incomplete else '1;32', color)}",
        f"  Variables : {_paint(variable_state, '1;32' if result.get('variables_decrypted') else '1;31', color)}",
        (
            f"  Stratégies analysées : {_paint(result.get('policies_downloaded', 0), '1;32', color)}"
            f"/{result.get('policy_assignments', 0)}"
            if result.get('policy_collection_attempted') else "  Stratégies : non interrogées dans ce rapport"
        ),
    ]
    if detailed:
        lines.extend([
            "  Périmètre : variables PXE et stratégies demandées avec le certificat du média pour l'identité Unknown Computer.",
            "  Ce contrôle ne valide ni toutes les stratégies du site, ni l'efficacité de tous les contrôles d'accès.",
        ])
        if result.get("variables_source"):
            lines.append(f"  Source : {public_text(result['variables_source'])}")
        if result.get("variables_sha256"):
            lines.append(f"  SHA-256 du fichier chiffré : {result['variables_sha256']}")
    lines.extend(["", _paint("Variables du .boot.var (valeurs complètes)", "1;36", color)])
    if not variables:
        lines.append("  Inventaire indisponible.")
    for number, item in enumerate(variables if detailed else variables[:32], 1):
        name = str(item["name"])
        sensitive = any(token in name.casefold() for token in ("pfx", "guid", "password", "secret"))
        value_code = "1;35" if sensitive else "0;37"
        lines.append(f"  {_paint(f'┌─ {number:02d}  {name}', '36', color)}")
        lines.append(
            f"  {_paint('│ valeur :', '35' if sensitive else '36', color)} "
            f"{name} = {_paint(item['display'], value_code, color)}"
        )
        if detailed:
            lines.append(
                f"  {_paint('└ rôle :', '35' if sensitive else '36', color)} "
                f"{item['description']} ({item['characters']} caractères dans la valeur source)"
            )
    if not detailed and len(variables) > 32:
        lines.append(f"  ... {len(variables) - 32} autres variables dans le rapport.")
    lines.extend(["", _paint("Alertes de sécurité", "1;36", color)])
    if not findings:
        lines.append("  Aucune alerte détectée dans les données analysées; ce n'est pas une certification de sécurité.")
    grouped = Counter((item['severity'], item['category'], item.get('key')) for item in findings)
    groups = sorted(grouped.items(), key=lambda item: {"critical": 0, "high": 1, "medium": 2}.get(item[0][0], 3))
    for (severity, category, key), count in groups if detailed else groups[:20]:
        label = {"critical": "CRITIQUE", "high": "ÉLEVÉ", "medium": "MOYEN"}.get(severity, severity.upper())
        severity_code = {"CRITIQUE": "1;31", "ÉLEVÉ": "1;33", "MOYEN": "1;35"}.get(label, "1;37")
        lines.append(
            f"  [{_paint(label, severity_code, color)}] {public_text(category)}"
            + (f" — {public_text(key)}" if key else "") + f" ({count})"
        )
        lines.append(f"    Action : {finding_guidance(category)}")
        if detailed:
            sources = dict.fromkeys(
                public_text(item['path']) for item in findings
                if (item['severity'], item['category'], item.get('key')) == (severity, category, key)
            )
            lines.extend(f"    Source : {path}" for path in sources)
    if not detailed and len(groups) > 20:
        lines.append(f"  ... {len(groups) - 20} autres types d'alertes dans le rapport.")
    lines.extend(["", _paint("Limites et erreurs (distinctes des alertes)", "1;36", color)])
    if not incomplete:
        lines.append("  Aucune erreur de collecte ou de décodage signalée.")
    for reason in incomplete if detailed else incomplete[:20]:
        lines.append(f"  - {public_text(reason)}")
    if not detailed and len(incomplete) > 20:
        lines.append(f"  ... {len(incomplete) - 20} autres erreurs dans le rapport.")
    if detailed:
        policies = result.get("policy_details")
        if isinstance(policies, list) and policies:
            lines.extend(["", _paint("Inventaire des stratégies", "1;36", color)])
            for item in policies:
                status_code = "1;32" if item["status"] == "analysée" else "1;31"
                lines.append(
                    f"  #{item['number']} [{_paint(item['status'], status_code, color)}] {item['category']} "
                    f"— référence {item['reference']}; origine {item['origin']}"
                )
                if item.get("error"):
                    lines.append(f"    Erreur ({item.get('error_stage') or 'étape non précisée'}) : {item['error']}")
                payloads = item.get("payloads")
                if isinstance(payloads, list):
                    for payload_number, payload in enumerate(payloads, 1):
                        lines.append(f"    {_paint(f'Contenu décodé #{payload_number} :', '36', color)}")
                        lines.append(_paint(str(payload), "0;37", color))
        lines.extend([
            "", "Mode audit local : les valeurs, secrets et PFX sont affichés sur demande explicite de l'opérateur.",
            "Référence de durcissement : https://learn.microsoft.com/en-us/intune/configmgr/osd/plan-design/security-and-privacy-for-operating-system-deployment",
        ])
    return "\n".join(lines)


def write_configmgr_report(directory: Path, result: dict[str, object]) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    path = directory / "configmgr-report.txt"
    timestamp = datetime.now(UTC).isoformat(timespec="seconds")
    data = (f"Rapport généré le {timestamp}\n\n" + render_configmgr_report(result) + "\n").encode("utf-8")
    try:
        _write_private(path, data)
    except FileExistsError:
        # Explicit --output directories can be reused; retain earlier reports.
        path = directory / f"configmgr-report-{uuid4().hex[:12]}.txt"
        _write_private(path, data)
    return path
