from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path
from typing import Any, TextIO

from .models import TraceEvent


class Tracer:
    def __init__(self, *, verbose: bool = False, compact: bool = False, stream: TextIO | None = None) -> None:
        self.verbose = verbose
        self.compact = compact
        self.stream = stream or sys.stderr
        self.color = bool(getattr(self.stream, "isatty", lambda: False)()) and not os.environ.get("NO_COLOR")
        self.started = time.monotonic()
        self.events: list[TraceEvent] = []

    def emit(self, phase: str, message: str, *, level: str = "info", **details: Any) -> None:
        event = TraceEvent(
            elapsed_ms=round((time.monotonic() - self.started) * 1000),
            phase=phase,
            level=level,
            message=message,
            details=details,
        )
        self.events.append(event)
        if self.verbose:
            suffix = ""
            if details:
                display_details = {
                    key: (f"<{len(value) // 2} bytes in JSON report>" if key.endswith("_hex") and isinstance(value, str) else value)
                    for key, value in details.items()
                }
                suffix = " " + " ".join(f"{key}={value!r}" for key, value in display_details.items())
            print(f"[{event.elapsed_ms:>6} ms] {level.upper():7} {phase}: {message}{suffix}", file=self.stream)
        elif self.compact and (level in {"warning", "error"} or phase in _COMPACT_PHASES):
            print(_compact_line(phase, message, level, details, color=self.color), file=self.stream)
        elif level in {"warning", "error"}:
            print(_compact_line(phase, message, level, details, color=self.color), file=self.stream)

    def write_json(self, path: Path, *, summary: dict[str, Any]) -> None:
        from .configmgr import _write_private

        document = {"summary": summary, "events": [event.as_dict() for event in self.events]}
        path.parent.mkdir(parents=True, exist_ok=True)
        _write_private(path, (json.dumps(document, indent=2, ensure_ascii=False) + "\n").encode("utf-8"))


_COMPACT_PHASES = {
    "identity.mac",
    "dhcp.discover",
    "dhcp.offer",
    "dhcp.request",
    "dhcp.ack",
    "dhcp.proxy-reply",
    "pxe.discover",
    "pxe.reply",
    "wds.request",
    "wds.reply",
    "wds.retry",
    "wds.wait",
    "tftp.rrq",
    "tftp.done",
    "http.get",
    "http.done",
    "bcd.decoded",
    "configmgr.variables",
    "configmgr.policies",
    "configmgr.done",
    "configmgr.warning",
    "audit.start",
    "audit.wim",
    "audit.wim-image",
    "audit.finding",
    "audit.clean",
    "audit.done",
    "audit.warning",
    "ipxe.stage2",
    "replay",
}


def _paint(text: str, code: str, enabled: bool) -> str:
    return f"\x1b[{code}m{text}\x1b[0m" if enabled else text


def _size(value: object) -> str:
    try:
        size = float(value)  # type: ignore[arg-type]
    except (TypeError, ValueError):
        return str(value)
    units = ("o", "Kio", "Mio", "Gio")
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.0f} {unit}" if unit == "o" else f"{size:.1f} {unit}"
        size /= 1024
    return str(value)


def _compact_line(
    phase: str,
    message: str,
    level: str,
    details: dict[str, Any],
    *,
    color: bool = False,
) -> str:
    label = phase.split(".", 1)[0].upper()
    text = message
    code = "36"
    child = False
    marker = "+"

    if phase == "identity.mac":
        label = "PXETRACE"
        text = f"MAC matérielle {details.get('pxe_mac')} (active sous Linux: {details.get('active_mac')})"
    elif phase == "dhcp.discover":
        text = f"recherche PXE, tentative {details.get('attempt')} (délai {details.get('wait_seconds'):g}s)"
    elif phase == "dhcp.offer":
        if details.get("boot_file"):
            label = "PXE"
            text = f"offre reçue: {details.get('boot_file')}"
        else:
            text = f"bail proposé: {details.get('yiaddr')}"
            child = True
        code = "32"
    elif phase == "dhcp.request":
        text = f"demande du bail {details.get('requested_ip')}"
    elif phase == "dhcp.ack":
        text = f"bail confirmé: {details.get('yiaddr')}"
        code = "32"
        child = True
    elif phase == "dhcp.proxy-reply":
        label = "PXE"
        text = f"réponse ProxyDHCP de {details.get('source')}: {details.get('boot_file') or 'sans fichier'}"
        code = "32"
    elif phase == "pxe.discover" and level == "info":
        text = f"interrogation de {details.get('server')}"
    elif phase == "pxe.reply":
        text = f"réponse de {details.get('source')}: {details.get('boot_file')}"
        code = "32"
    elif phase == "wds.request" and level == "info":
        text = f"demande de configuration à {details.get('server')}"
    elif phase == "wds.reply":
        child = True
        if details.get("bcd_path"):
            text = f"BCD annoncé: {details.get('bcd_path')}"
            if details.get("boot_file"):
                text += f" (chargeur: {details.get('boot_file')})"
            code = "32"
        else:
            text = f"réponse intermédiaire: {details.get('status') or 'politique en préparation'}"
    elif phase == "wds.wait":
        text = f"{message}; nouvelle tentative dans {details.get('wait_seconds'):g}s"
        child = True
    elif phase == "tftp.rrq":
        text = f"lecture de {details.get('filename')} sur {details.get('server')}"
    elif phase == "tftp.done":
        text = f"reçu {_size(details.get('bytes'))}"
        code = "32"
        child = True
    elif phase == "tftp.progress":
        total = details.get("total_bytes")
        text = f"{_size(details.get('bytes'))} reçus"
        if total:
            try:
                text += f" ({float(details.get('bytes', 0)) / float(total):.0%})"
            except (TypeError, ValueError, ZeroDivisionError):
                pass
        child = True
    elif phase == "http.get":
        text = f"lecture de {details.get('uri')}"
    elif phase == "http.done":
        text = f"reçu {_size(details.get('bytes'))}"
        code = "32"
        child = True
    elif phase == "bcd.decoded":
        text = f"{details.get('objects')} objets décodés, {details.get('references')} fichiers référencés"
        code = "32"
    elif phase == "configmgr.variables":
        label = "CONFIGMGR"
        text = f"variables analysées en mémoire, {details.get('management_points')} point(s) de gestion"
        code = "32"
    elif phase == "configmgr.policies":
        label = "CONFIGMGR"
        text = "lecture des affectations de stratégies"
    elif phase == "configmgr.done":
        label = "CONFIGMGR"
        text = (
            f"{details.get('downloaded')}/{details.get('assignments')} stratégie(s) analysée(s)"
        )
        code = "32" if not details.get("failed") else "33"
    elif phase == "audit.start":
        label = "AUDIT"
        text = "recherche de secrets dans les fichiers de démarrage"
    elif phase == "audit.wim":
        label = "AUDIT"
        text = f"inspection de {str(details.get('path')).rsplit('/', 1)[-1]}"
        child = True
    elif phase == "audit.wim-image":
        label = "AUDIT"
        text = f"image {details.get('image')}: {details.get('files')} fichier(s) vérifié(s)"
        child = True
    elif phase == "audit.finding":
        label = "AUDIT"
        key = f" ({details.get('key')})" if details.get("key") else ""
        text = f"{message}: {details.get('path')}{key} — valeur masquée"
        child = True
    elif phase == "audit.clean":
        label = "AUDIT"
        text = f"aucune exposition détectée ({details.get('files')} fichier(s) vérifié(s))"
        code = "32"
        child = True
    elif phase == "audit.done":
        label = "AUDIT"
        text = f"{details.get('findings')} alerte(s), {details.get('files')} fichier(s) vérifié(s); valeurs masquées"
        child = True
    elif phase == "audit.warning":
        label = "AUDIT"
        child = True
    elif phase == "replay":
        label = "PXETRACE"
        text = f"reprise depuis {details.get('uri')}"

    if level == "error":
        if phase.startswith("fetch."):
            uri = str(details.get("uri") or "")
            if uri.startswith("tftp:"):
                label = "TFTP"
            elif uri.startswith(("http:", "https:")):
                label = "HTTP"
            child = True
        code = "31"
        marker = "!"
        subject = details.get("uri") or details.get("server")
        reason = details.get("reason")
        text = str(reason or message)
        if subject and not child and str(subject) not in text:
            text += f" ({subject})"
    elif level == "warning":
        code = "33"
        marker = "!"
        if phase != "audit.finding":
            text = message
            if details.get("reason"):
                text += f": {details.get('reason')}"
        if phase.startswith("dhcp.") or phase.startswith("tftp.") or phase.startswith("fetch."):
            child = True

    prefix = f"[{label}]"
    if child:
        indentation = " " * (len(prefix) + 1)
        return f"{indentation}{_paint(f'[{marker}]', code, color)} {text}"
    if level in {"warning", "error"}:
        text = f"[{marker}] {text}"
    return f"{_paint(prefix, code, color)} {text}"
