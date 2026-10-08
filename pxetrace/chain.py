from __future__ import annotations

import hashlib
import re
import shlex
import urllib.parse
from collections import deque

from .bcd import BcdError, decode_bcd
from .models import BootTarget
from .trace import Tracer
from .transfer import Fetcher, TransferError, resolve_reference

_URI_OR_BOOT_PATH = re.compile(
    rb"(?:(?:https?|tftp)://[A-Za-z0-9._~:/?#\[\]@!$&'()*+,;=%-]{4,}|"
    rb"(?:[/\\])?(?:[A-Za-z0-9_.-]+(?:/|\\))*"
    rb"(?:[A-Za-z0-9_.-]+\.(?:efi|cfg|ipxe|kpxe|wim|sdi|bcd|exe|com|n12)|BCD))"
)
_UTF16LE_STRING = re.compile(rb"(?:[\x20-\x7e]\x00){4,}")


def _text(data: bytes) -> str | None:
    if data.startswith((b"#!ipxe", b"#!gpxe")):
        return data.decode("utf-8", "replace")
    if data.startswith((b"\xff\xfe", b"\xfe\xff")):
        try:
            return data.decode("utf-16")
        except UnicodeError:
            return None
    sample = data[:4096]
    if not sample:
        return ""
    printable = sum(byte in b"\t\n\r" or 32 <= byte < 127 or byte >= 0xC0 for byte in sample)
    if printable / len(sample) > 0.85 and b"\0" not in sample:
        return data.decode("utf-8", "replace")
    return None


def detect_kind(uri: str, data: bytes) -> str:
    path = urllib.parse.urlsplit(uri).path.lower()
    text = _text(data[:16384])
    if data.startswith((b"#!ipxe", b"#!gpxe")) or path.endswith((".ipxe", ".gpxe")):
        return "ipxe-script"
    if path.endswith(("grub.cfg", "/menu.lst")) or (text and re.search(r"(?m)^\s*(menuentry|linuxefi|insmod)\b", text)):
        return "grub-config"
    if "pxelinux.cfg" in path or (text and re.search(r"(?mi)^\s*(default|label|kernel|append)\s+", text)):
        return "pxelinux-config"
    if data.startswith(b"MZ"):
        return "uefi-pe"
    if path.endswith((".efi", ".0")):
        return "boot-program"
    if path.endswith(("vmlinuz", ".kernel")) or "/vmlinuz" in path:
        return "kernel"
    if path.endswith((".img", ".initrd", ".gz", ".xz")):
        return "initrd-or-image"
    if path.endswith(".wim"):
        return "windows-image"
    if path.endswith(".sdi"):
        return "windows-ramdisk"
    if path.endswith("bcd"):
        return "windows-bcd"
    return "text" if text is not None else "binary"


def _strip_comment(line: str) -> str:
    # PXE config files use # comments; quoted # is uncommon but shlex handles it.
    try:
        tokens = shlex.split(line, comments=True, posix=True)
    except ValueError:
        return ""
    return " ".join(tokens)


def _command_reference(tokens: list[str]) -> str | None:
    index = 1
    while index < len(tokens):
        token = tokens[index]
        if token == "--":
            index += 1
            break
        if not token.startswith("-"):
            break
        # iPXE options which consume the following argument.
        if token in {"-n", "--name", "-t", "--timeout", "--autofree"} and token != "--autofree":
            index += 2
        else:
            index += 1
    return tokens[index] if index < len(tokens) else None


def parse_ipxe(base_uri: str, text: str, initial_variables: dict[str, str] | None = None) -> list[BootTarget]:
    targets: list[BootTarget] = []
    variables: dict[str, str] = dict(initial_variables or {})
    for raw_line in text.splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        try:
            tokens = shlex.split(line, comments=True, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        command = tokens[0].lower()
        if command == "set" and len(tokens) >= 3:
            variables[tokens[1]] = " ".join(tokens[2:])
            continue
        for name, value in variables.items():
            tokens = [token.replace("${" + name + "}", value) for token in tokens]
        if command not in {"chain", "kernel", "initrd", "imgfetch", "module", "config"}:
            continue
        reference = _command_reference(tokens)
        if not reference:
            continue
        uri = resolve_reference(base_uri, reference)
        kind = {
            "chain": "script-or-program",
            "config": "config",
            "kernel": "kernel",
            "initrd": "initrd",
            "imgfetch": "image",
            "module": "module",
        }[command]
        certainty = "unresolved" if "${" in uri else "certain"
        targets.append(BootTarget(uri=uri, kind=kind, source=f"iPXE:{command}", certainty=certainty, parent=base_uri))
    return targets


def parse_grub(base_uri: str, text: str) -> list[BootTarget]:
    targets: list[BootTarget] = []
    variables: dict[str, str] = {}
    for raw_line in text.splitlines():
        clean = _strip_comment(raw_line)
        if not clean:
            continue
        try:
            tokens = shlex.split(clean, posix=True)
        except ValueError:
            continue
        if not tokens:
            continue
        command = tokens[0].lower()
        if command == "set" and len(tokens) >= 2 and "=" in tokens[1]:
            key, value = tokens[1].split("=", 1)
            variables[key] = value
            continue
        if command not in {"linux", "linuxefi", "initrd", "initrdefi", "chainloader", "configfile", "source"}:
            continue
        reference = next((token for token in tokens[1:] if not token.startswith("-")), None)
        if not reference:
            continue
        for name, value in variables.items():
            reference = reference.replace("${" + name + "}", value).replace("$" + name, value)
        device_match = re.match(r"^\((tftp|http|https),([^,)]+)(?:,[^)]*)?\)(.*)$", reference, re.IGNORECASE)
        if device_match:
            scheme, host, path = device_match.groups()
            uri = f"{scheme.lower()}://{host}/{path.lstrip('/')}"
        else:
            reference = re.sub(r"^\([^)]*\)", "", reference)
            uri = resolve_reference(base_uri, reference)
        kind = "kernel" if command.startswith("linux") else "initrd" if command.startswith("initrd") else "config-or-program"
        targets.append(
            BootTarget(
                uri=uri,
                kind=kind,
                source=f"GRUB:{command}",
                certainty="unresolved" if "$" in uri else "certain",
                parent=base_uri,
            )
        )
    return targets


def parse_pxelinux(base_uri: str, text: str) -> list[BootTarget]:
    targets: list[BootTarget] = []
    for raw_line in text.splitlines():
        clean = _strip_comment(raw_line)
        if not clean:
            continue
        parts = clean.split(None, 1)
        if len(parts) != 2:
            continue
        command, arguments = parts[0].upper(), parts[1].strip()
        references: list[tuple[str, str]] = []
        if command in {"KERNEL", "LINUX", "COM32", "CONFIG", "INCLUDE"}:
            references.append((arguments.split()[0], "kernel" if command in {"KERNEL", "LINUX"} else "config-or-program"))
        elif command == "INITRD":
            references.extend((item.strip(), "initrd") for item in arguments.split(","))
        elif command == "APPEND":
            match = re.search(r"(?:^|\s)initrd=([^\s]+)", arguments, re.IGNORECASE)
            if match:
                references.extend((item.strip(), "initrd") for item in match.group(1).split(","))
        for reference, kind in references:
            targets.append(
                BootTarget(
                    uri=resolve_reference(base_uri, reference),
                    kind=kind,
                    source=f"PXELINUX:{command}",
                    parent=base_uri,
                )
            )
    return targets


def binary_hints(base_uri: str, data: bytes) -> list[BootTarget]:
    """Extract hints only; binary strings do not prove an execution edge."""
    source_name = urllib.parse.urlsplit(base_uri).path.rsplit("/", 1)[-1].lower()
    candidates: set[str] = set()
    for match in _URI_OR_BOOT_PATH.finditer(data):
        candidates.add(match.group().decode("ascii", "replace"))
    # Also inspect individually aligned UTF-16LE strings, frequent in EFI
    # applications; slicing the whole binary would miss odd-aligned strings.
    for wide in _UTF16LE_STRING.finditer(data):
        ascii_string = wide.group()[::2]
        for match in _URI_OR_BOOT_PATH.finditer(ascii_string):
            candidates.add(match.group().decode("ascii", "replace"))
    targets: list[BootTarget] = []
    for candidate in sorted(candidates)[:100]:
        path = urllib.parse.urlsplit(candidate).path.lower().replace("\\", "/")
        basename = path.rsplit("/", 1)[-1]
        # These are actual boot-chain containers/resources. Following them is
        # required to reach a Windows WIM without executing bootmgfw/bootmgr.
        known_efi = basename.startswith(("boot", "wdsmgfw", "winload", "pxeboot")) and basename.endswith(".efi")
        known_wim = (basename.startswith("boot") and basename.endswith(".wim")) or "/smsimages/" in path
        inferred = basename == "bcd" or path.endswith(("/bcd", ".bcd", ".sdi", ".ipxe", ".kpxe", ".cfg")) or known_efi or known_wim or (
            basename.startswith(("bootmgr", "wdsnbp", "pxeboot", "abortpxe"))
            and basename.endswith((".exe", ".com", ".n12"))
        )
        # wdsmgfw obtains a client-specific BCD through its UDP/4011 WDS
        # exchange.  Generic BCD strings embedded in the PE are fallbacks and
        # must not be mistaken for the actual execution edge.
        if source_name == "wdsmgfw.efi":
            inferred = False
        targets.append(
            BootTarget(
                uri=resolve_reference(base_uri, candidate),
                kind="binary-string-hint",
                source="binary-string",
                certainty="inferred" if inferred else "heuristic",
                parent=base_uri,
            )
        )
    return targets


def windows_boot_manager_hints(base_uri: str) -> list[BootTarget]:
    """Return implicit BCD locations used by the Windows boot managers."""
    name = urllib.parse.urlsplit(base_uri).path.rsplit("/", 1)[-1].lower()
    if name not in {"bootmgfw.efi", "bootmgr.efi", "bootmgr.exe", "bootmgr"}:
        return []
    return [
        BootTarget(
            uri=resolve_reference(base_uri, "BCD"),
            kind="windows-bcd",
            source=f"Windows boot-manager convention:{name}",
            certainty="inferred",
            parent=base_uri,
        )
    ]


class ChainTracer:
    def __init__(
        self,
        fetcher: Fetcher,
        tracer: Tracer,
        *,
        max_depth: int = 8,
        max_files: int = 128,
        follow_heuristics: bool = False,
        variables: dict[str, str] | None = None,
        max_inspect_bytes: int = 64 * 1024 * 1024,
        windows_bcd_uri: str | None = None,
    ) -> None:
        self.fetcher = fetcher
        self.tracer = tracer
        self.max_depth = max_depth
        self.max_files = max_files
        self.follow_heuristics = follow_heuristics
        self.variables = dict(variables or {})
        self.max_inspect_bytes = max_inspect_bytes
        self.windows_bcd_uri = windows_bcd_uri
        self._seen: set[str] = set()
        self._fetch_attempts = 0
        self._limit_reported = False

    def trace(self, initial: BootTarget) -> list[BootTarget]:
        graph: list[BootTarget] = []
        queue: deque[tuple[BootTarget, int]] = deque([(initial, 0)])
        while queue:
            target, depth = queue.popleft()
            if target.uri in self._seen:
                continue
            self._seen.add(target.uri)
            graph.append(target)
            if target.certainty == "unresolved":
                target.status = "unresolved"
                self.tracer.emit(
                    "chain.unresolved",
                    "référence contenant une variable non résolue",
                    level="warning",
                    uri=target.uri,
                    parent=target.parent,
                )
                continue
            if target.certainty == "heuristic" and not self.follow_heuristics:
                target.status = "heuristic-skipped"
                self.tracer.emit(
                    "chain.hint",
                    "chaîne trouvée dans un binaire; non téléchargée car le lien d'exécution n'est pas prouvé",
                    uri=target.uri,
                    parent=target.parent,
                )
                continue
            if depth > self.max_depth:
                target.status = "depth-limited"
                self.tracer.emit("chain.limit", "profondeur maximale atteinte", level="warning", uri=target.uri)
                continue
            if self._fetch_attempts >= self.max_files:
                target.status = "transfer-limit"
                if not self._limit_reported:
                    self.tracer.emit(
                        "chain.limit",
                        "nombre maximal de transferts atteint",
                        level="warning",
                        limit=self.max_files,
                    )
                    self._limit_reported = True
                continue
            self._fetch_attempts += 1
            try:
                fetched = self.fetcher.fetch(target.uri)
            except (TransferError, OSError) as exc:
                target.status = "failed"
                target.error = str(exc)
                failed_uri_path = urllib.parse.urlsplit(target.uri).path.lower()
                critical_boot_resource = target.kind in {
                    "bcd-boot-resource",
                    "windows-image",
                    "windows-ramdisk",
                } or failed_uri_path.endswith((".wim", ".sdi"))
                if target.certainty == "inferred" and not critical_boot_resource:
                    self.tracer.emit(
                        "fetch.optional-miss",
                        "ressource déduite indisponible",
                        uri=target.uri,
                        parent=target.parent,
                        reason=str(exc),
                    )
                else:
                    self.tracer.emit("fetch.error", str(exc), level="error", uri=target.uri, parent=target.parent)
                continue
            path = fetched.path
            size = fetched.size
            target.local_path = path
            target.status = "downloaded"
            try:
                if fetched.sha256 is not None:
                    with path.open("rb") as downloaded:
                        data = downloaded.read(self.max_inspect_bytes)
                    checksum = fetched.sha256
                else:
                    digest = hashlib.sha256()
                    inspected = bytearray()
                    with path.open("rb") as downloaded:
                        while chunk := downloaded.read(1024 * 1024):
                            digest.update(chunk)
                            remaining = self.max_inspect_bytes - len(inspected)
                            if remaining > 0:
                                inspected.extend(chunk[:remaining])
                    data = bytes(inspected)
                    checksum = digest.hexdigest()
                target.size_bytes = path.stat().st_size
            except OSError as exc:
                target.status = "inspection-failed"
                target.error = str(exc)
                self.tracer.emit(
                    "chain.inspect-error",
                    "objet téléchargé mais impossible à relire",
                    level="error",
                    uri=target.uri,
                    reason=str(exc),
                )
                continue
            target.sha256 = checksum
            detected_kind = detect_kind(target.uri, data)
            if target.kind == "configmgr-variables":
                target.metadata["detected_kind"] = detected_kind
            else:
                target.kind = detected_kind
            self.tracer.emit(
                "chain.inspect",
                "objet identifié",
                uri=target.uri,
                kind=target.kind,
                bytes=size,
                sha256=target.sha256,
                depth=depth,
                inspected_bytes=len(data),
            )
            if target.size_bytes is not None and target.size_bytes > len(data):
                self.tracer.emit(
                    "chain.inspect-limit",
                    "analyse de contenu limitée; le hachage couvre néanmoins le fichier entier",
                    uri=target.uri,
                    total_bytes=target.size_bytes,
                    inspected_bytes=len(data),
                )
            text = _text(data)
            children: list[BootTarget]
            if target.kind == "ipxe-script" and text is not None:
                children = parse_ipxe(target.uri, text, self.variables)
            elif target.kind == "grub-config" and text is not None:
                children = parse_grub(target.uri, text)
            elif target.kind == "pxelinux-config" and text is not None:
                children = parse_pxelinux(target.uri, text)
            elif target.kind == "windows-bcd":
                try:
                    bcd_report, references = decode_bcd(data)
                except BcdError as exc:
                    target.metadata["bcd_error"] = str(exc)
                    self.tracer.emit(
                        "bcd.decode-error",
                        "le fichier BCD a été téléchargé mais son décodage a échoué",
                        level="error",
                        uri=target.uri,
                        reason=str(exc),
                    )
                    # Keep a degraded but useful path to the two resources a
                    # Windows ramdisk BCD selects.  Do not recursively follow
                    # generic BCD strings from a malformed hive.
                    children = [
                        child
                        for child in binary_hints(target.uri, data)
                        if urllib.parse.urlsplit(child.uri).path.lower().endswith((".wim", ".sdi"))
                    ]
                else:
                    target.metadata["bcd"] = bcd_report
                    target.metadata["bcd_decoded"] = True
                    self.tracer.emit(
                        "bcd.decoded",
                        "magasin BCD décodé",
                        uri=target.uri,
                        objects=len(bcd_report["objects"]),
                        references=len(references),
                        dirty=bcd_report["dirty"],
                    )
                    children = [
                        BootTarget(
                            uri=resolve_reference(target.uri, reference["path"]),
                            kind="bcd-boot-resource",
                            source=f"BCD:{reference['element']}:{reference['element_name']}",
                            certainty="certain",
                            parent=target.uri,
                            metadata={"bcd_reference": reference},
                        )
                        for reference in references
                    ]
            elif target.kind in {"uefi-pe", "boot-program", "binary"}:
                target_name = urllib.parse.urlsplit(target.uri).path.rsplit("/", 1)[-1].lower()
                if target_name == "wdsmgfw.efi":
                    # Its real next edge is obtained by replaying the WDS NBP
                    # exchange on UDP/4011.  Embedded PE strings are not paths
                    # selected for this client.
                    children = []
                else:
                    children = binary_hints(target.uri, data)
                if self.windows_bcd_uri and target_name in {
                    "bootmgfw.efi",
                    "bootmgr.efi",
                    "bootmgr.exe",
                    "bootmgr",
                }:
                    for child in children:
                        child.certainty = "heuristic"
                    children = [
                        child
                        for child in children
                        if not urllib.parse.urlsplit(child.uri).path.lower().endswith(("/bcd", ".bcd"))
                    ]
                    children.append(
                        BootTarget(
                            uri=self.windows_bcd_uri,
                            kind="windows-bcd",
                            source="WDS option 252",
                            certainty="certain",
                            parent=target.uri,
                        )
                    )
                else:
                    known_uris = {child.uri for child in children}
                    children.extend(
                        child for child in windows_boot_manager_hints(target.uri) if child.uri not in known_uris
                    )
            else:
                children = []
            for child in children:
                self.tracer.emit(
                    "chain.edge",
                    "prochaine ressource identifiée",
                    parent=target.uri,
                    child=child.uri,
                    source=child.source,
                    certainty=child.certainty,
                )
                queue.append((child, depth + 1))
        return graph
