"""Short client-facing report; full evidence remains in the local report."""
from __future__ import annotations

import shutil
from collections import Counter
from typing import Any

from .configmgr_report import public_text


def table(headers: list[str], rows: list[list[str]], *, width: int = 110) -> list[str]:
    """Wrap values, including long passwords; never elide evidence."""
    widths = [max(len(header), min(32, max((len(row[i]) for row in rows), default=0))) for i, header in enumerate(headers)]
    while sum(widths) + 3 * len(widths) + 1 > max(width, 50):
        largest = max(range(len(widths)), key=lambda i: widths[i])
        if widths[largest] <= 8:
            break
        widths[largest] -= 1
    border = "+" + "+".join("-" * (size + 2) for size in widths) + "+"
    output = [border]
    for number, row in enumerate([headers, *rows]):
        cells = [[value[offset:offset + size] for offset in range(0, len(value), size)] or [""] for value, size in zip(row, widths)]
        for line in range(max(map(len, cells))):
            output.append("| " + " | ".join((cell[line] if line < len(cell) else "").ljust(size) for cell, size in zip(cells, widths)) + " |")
        if number == 0:
            output.append(border)
    output.append(border)
    return output


def render_audit_screen(summary: dict[str, Any], *, color: bool = False) -> str:
    def paint(text: str, code: str) -> str:
        return f"\x1b[{code}m{text}\x1b[0m" if color else text

    boot = summary.get("boot") or summary.get("replay") or {}
    server = boot.get("effective_boot_server") or boot.get("source") or boot.get("uri") or "non identifié"
    config = summary.get("configmgr") or {}
    images = summary.get("image_audit") or {}
    findings = [*config.get("findings", []), *images.get("findings", [])]
    evidence = [*config.get("credentials", []), *images.get("credentials", [])]
    # One row per credential, even when it appears in dozens of policies.
    # All occurrences and contexts stay available in the detailed report.
    grouped: dict[tuple[str, str, str], list[dict[str, Any]]] = {}
    for item in evidence:
        key = (item["account"], item["secret"], item.get("kind", "mot de passe"))
        grouped.setdefault(key, []).append(item)
    evidence = [items[0] for items in grouped.values()]
    lines = ["", paint("PXETRACE — AUDIT PXE", "1;36"), "Serveur : " + public_text(server)]
    if summary.get("offline"):
        lines.append("Mode : hors ligne — aucune vérification de l'état actuel du serveur")
    if summary.get("demo"):
        lines.append(paint("DÉMONSTRATION — identifiants fictifs", "1;33"))
    lines.append("")
    lines.append(paint(f"{len(evidence)} secret(s) extrait(s) en clair", "1;31" if evidence else "1;33"))
    if evidence:
        sources = list(dict.fromkeys(item["source"] for item in evidence))
        rows = []
        repeated = False
        for items in grouped.values():
            item = items[0]
            others = len({entry["source"] for entry in items}) - 1
            reference = str(sources.index(item["source"]) + 1)
            if others:
                reference += f" (+{others})"
                repeated = True
            rows.append([public_text(item["account"]), public_text(item["secret"]), public_text(item["field"]), reference])
        lines.extend(table(["Compte", "Secret en clair", "Champ", "Source"], rows,
                           width=shutil.get_terminal_size((110, 24)).columns))
        lines.extend(f"  [{number}] {public_text(source)}" for number, source in enumerate(sources, 1))
        if repeated:
            lines.append("  +N : autres sources du même secret, conservées dans le rapport détaillé.")
        lines.append("Valeurs extraites des fichiers ; validité des comptes non testée.")
    else:
        lines.append("Aucun secret extrait des contenus analysés ; ce n'est pas une garantie d'absence.")
    if findings:
        lines.extend(["", paint("Alertes de sécurité", "1;33")])
        occurrences = {(item["severity"], item["category"], item.get("path", "")) for item in findings}
        groups = Counter((severity, category) for severity, category, _ in occurrences)
        for (severity, category), count in sorted(groups.items(), key=lambda item: {"critical": 0, "high": 1}.get(item[0][0], 2)):
            label = {"critical": "CRITIQUE", "high": "ÉLEVÉ", "medium": "MOYEN"}.get(severity, severity)
            lines.append("  " + paint(label, "31" if severity == "critical" else "33") + "  " + public_text(category) + (f" ({count})" if count > 1 else ""))
    lines.extend(["", paint("Couverture", "1;36")])
    if config:
        policies = f"{config.get('policies_downloaded', 0)}/{config.get('policy_assignments', 0)} stratégies analysées"
        lines.append("  ConfigMgr : " + policies + (" ; variables décodées" if config.get("variables_decrypted") else " ; variables non décodées"))
        failed = Counter(item["category"] for item in config.get("policy_details", []) if item.get("error"))
        if failed:
            categories = list(failed.items())
            text = ", ".join(f"{public_text(category)} × {count}" for category, count in categories[:4])
            if len(categories) > 4:
                text += f", +{len(categories) - 4} catégories"
            lines.append("  Non analysées : " + text + ". Secrets éventuels non vérifiés.")
        if config.get("incomplete") and not failed:
            lines.append(f"  ConfigMgr incomplet ({len(config['incomplete'])} erreur(s)); détails dans le rapport.")
        elif len(config.get("incomplete", [])) > sum(failed.values()):
            lines.append("  Autres limites ConfigMgr : voir le rapport détaillé.")
    if images:
        read = images.get('scanned_files', 0)
        uninterpreted = images.get('uninterpreted', [])
        lines.append(f"  Images : {read} fichier(s) ciblé(s) lu(s), {max(0, read - len(uninterpreted))} interprété(s)")
        if images.get("inventories_read") and not images.get("known_configurations") and not images.get("incomplete"):
            lines.append("  Aucune configuration de déploiement connue trouvée dans les images inspectées.")
        if uninterpreted:
            counts = Counter(item["reason"] for item in uninterpreted)
            lines.append("  Non interprétés : " + ", ".join(f"{public_text(reason)} × {count}" for reason, count in counts.items()) + ".")
        if images.get("incomplete"):
            reasons: Counter[str] = Counter()
            for error in images["incomplete"]:
                if "wimlib-imagex absent" in error:
                    reason = "wimtools absent"
                elif "7z absent" in error:
                    reason = "7z absent"
                elif any(word in error for word in ("limite", "volumineux", "premiers index", "timed out")):
                    reason = "limite de lecture atteinte"
                else:
                    reason = "lecture impossible"
                reasons[reason] += 1
            lines.append("  Analyse partielle : " + ", ".join(f"{reason} × {count}" for reason, count in reasons.items()) + ". Détails dans le rapport.")
        if read or images.get("inventories_read") or images.get("incomplete"):
            lines.append("  Recherche ciblée ; une vérification manuelle peut compléter l'audit.")
        else:
            lines.append("  Aucune image ni configuration disponible pour cette analyse.")
    elif not config:
        lines.append("  Aucun contenu audité.")
    lines.append("Rapport : " + public_text(summary.get("audit_report_path") or summary.get("configmgr_report_path") or summary.get("output_path") or "non enregistré"))
    return "\n".join(lines)
