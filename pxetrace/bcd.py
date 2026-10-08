from __future__ import annotations

import re
import struct
import uuid
from dataclasses import dataclass
from typing import Any


class BcdError(ValueError):
    """Raised when a BCD registry hive is structurally invalid."""


_ELEMENT_NAMES = {
    0x11000001: "library.application_device",
    0x12000002: "library.application_path",
    0x12000004: "library.description",
    0x12000005: "library.locale",
    0x14000006: "library.inherit",
    0x14000008: "library.recovery_sequence",
    0x16000009: "library.recovery_enabled",
    0x21000001: "osloader.os_device",
    0x22000002: "osloader.system_root",
    0x26000010: "osloader.detect_kernel_and_hal",
    0x31000003: "ramdisk.sdi_device",
    0x32000004: "ramdisk.sdi_path",
}

_FORMATS = {
    1: "device",
    2: "string",
    3: "object",
    4: "object-list",
    5: "integer",
    6: "boolean",
    7: "integer-list",
}

_BOOT_PATH = re.compile(
    r"(?i)(?:[a-z]:)?[\\/][^\x00\r\n\"<>|]{1,1024}?(?:\.wim|\.sdi|[\\/]bcd)\b"
)


def _u16(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 2 > len(data):
        raise BcdError("champ 16 bits hors de la ruche")
    return struct.unpack_from("<H", data, offset)[0]


def _u32(data: bytes, offset: int) -> int:
    if offset < 0 or offset + 4 > len(data):
        raise BcdError("champ 32 bits hors de la ruche")
    return struct.unpack_from("<I", data, offset)[0]


def _decode_name(raw: bytes, compressed: bool) -> str:
    return raw.decode("latin-1" if compressed else "utf-16le", "replace")


def _utf16_strings(data: bytes, minimum: int = 3) -> list[str]:
    # Search both alignments: device elements may embed a UTF-16 string at an
    # odd byte offset inside their binary descriptor.
    pattern = re.compile(rb"(?:[\x20-\x7e]\x00){" + str(minimum).encode() + rb",}")
    values: list[str] = []
    for start in (0, 1):
        for match in pattern.finditer(data[start:]):
            text = match.group().decode("utf-16le", "replace").rstrip("\x00")
            if text and text not in values:
                values.append(text)
    return values


@dataclass(slots=True)
class _RegistryValue:
    name: str
    data_type: int
    data: bytes


class _Hive:
    """Minimal, bounded reader for the on-disk Windows registry hive format."""

    def __init__(self, data: bytes) -> None:
        if len(data) < 0x1000 or data[:4] != b"regf":
            raise BcdError("le fichier n'est pas une ruche de registre Windows (signature regf absente)")
        self.data = data
        self.root_offset = _u32(data, 0x24)
        self.sequence_primary = _u32(data, 0x04)
        self.sequence_secondary = _u32(data, 0x08)

    def cell(self, relative_offset: int) -> bytes:
        if relative_offset == 0xFFFFFFFF:
            raise BcdError("référence de cellule vide")
        absolute = 0x1000 + relative_offset
        if absolute < 0x1000 or absolute + 4 > len(self.data):
            raise BcdError(f"cellule 0x{relative_offset:08x} hors de la ruche")
        signed_size = struct.unpack_from("<i", self.data, absolute)[0]
        size = abs(signed_size)
        if size < 4 or absolute + size > len(self.data):
            raise BcdError(f"taille invalide pour la cellule 0x{relative_offset:08x}")
        return self.data[absolute + 4 : absolute + size]

    def _subkey_offsets(self, list_offset: int, *, depth: int = 0) -> list[int]:
        if depth > 16:
            raise BcdError("listes de sous-clés imbriquées trop profondément")
        cell = self.cell(list_offset)
        if len(cell) < 4:
            raise BcdError("liste de sous-clés tronquée")
        signature = cell[:2]
        count = _u16(cell, 2)
        if count > 65535:
            raise BcdError("nombre de sous-clés excessif")
        if signature in {b"lf", b"lh"}:
            width = 8
            if 4 + count * width > len(cell):
                raise BcdError("liste lf/lh tronquée")
            return [_u32(cell, 4 + index * width) for index in range(count)]
        if signature == b"li":
            if 4 + count * 4 > len(cell):
                raise BcdError("liste li tronquée")
            return [_u32(cell, 4 + index * 4) for index in range(count)]
        if signature == b"ri":
            if 4 + count * 4 > len(cell):
                raise BcdError("liste ri tronquée")
            result: list[int] = []
            for index in range(count):
                result.extend(self._subkey_offsets(_u32(cell, 4 + index * 4), depth=depth + 1))
            return result
        raise BcdError(f"type de liste de sous-clés inconnu: {signature!r}")

    def _value(self, offset: int) -> _RegistryValue:
        cell = self.cell(offset)
        if len(cell) < 0x14 or cell[:2] != b"vk":
            raise BcdError("cellule de valeur vk invalide")
        name_length = _u16(cell, 2)
        encoded_length = _u32(cell, 4)
        length = encoded_length & 0x7FFFFFFF
        data_offset = _u32(cell, 8)
        data_type = _u32(cell, 0x0C)
        flags = _u16(cell, 0x10)
        if 0x14 + name_length > len(cell):
            raise BcdError("nom de valeur tronqué")
        name = _decode_name(cell[0x14 : 0x14 + name_length], bool(flags & 1))
        if encoded_length & 0x80000000:
            if length > 4:
                raise BcdError("valeur résidente supérieure à quatre octets")
            raw = cell[8:12][:length]
        elif length:
            raw_cell = self.cell(data_offset)
            if length > len(raw_cell):
                raise BcdError("données de valeur tronquées")
            raw = raw_cell[:length]
        else:
            raw = b""
        return _RegistryValue(name, data_type, raw)

    def walk(self) -> tuple[str, list[tuple[str, _RegistryValue]]]:
        values: list[tuple[str, _RegistryValue]] = []
        visited: set[int] = set()

        def visit(offset: int, parent: str, depth: int) -> str:
            if depth > 128 or len(visited) > 100_000:
                raise BcdError("limite de parcours de la ruche atteinte")
            if offset in visited:
                raise BcdError("cycle de cellules détecté dans la ruche")
            visited.add(offset)
            cell = self.cell(offset)
            if len(cell) < 0x4C or cell[:2] != b"nk":
                raise BcdError("cellule de clé nk invalide")
            flags = _u16(cell, 2)
            name_length = _u16(cell, 0x48)
            if 0x4C + name_length > len(cell):
                raise BcdError("nom de clé tronqué")
            name = _decode_name(cell[0x4C : 0x4C + name_length], bool(flags & 0x20))
            path = f"{parent}/{name}" if parent else name

            value_count = _u32(cell, 0x24)
            if value_count > 100_000:
                raise BcdError("nombre de valeurs excessif")
            if value_count:
                value_list = self.cell(_u32(cell, 0x28))
                if value_count * 4 > len(value_list):
                    raise BcdError("liste de valeurs tronquée")
                for index in range(value_count):
                    values.append((path, self._value(_u32(value_list, index * 4))))

            subkey_count = _u32(cell, 0x14)
            if subkey_count:
                # An nk record has two subkey counts: stable at 0x14 and
                # volatile at 0x18.  Their list offsets are at 0x1c and 0x20.
                # On-disk BCD stores use the stable list; 0x18 is therefore a
                # count (usually zero), not a cell reference.
                offsets = self._subkey_offsets(_u32(cell, 0x1C))
                if len(offsets) != subkey_count:
                    raise BcdError("compte de sous-clés incohérent")
                for child in offsets:
                    visit(child, path, depth + 1)
            return name

        root_name = visit(self.root_offset, "", 0)
        return root_name, values


def _decode_element(element_id: int, data: bytes) -> tuple[str, Any, list[str]]:
    format_code = (element_id >> 24) & 0xF
    format_name = _FORMATS.get(format_code, f"unknown-{format_code}")
    paths: list[str] = []

    if format_code == 2:
        decoded: Any = data.decode("utf-16le", "replace").rstrip("\x00")
    elif format_code == 3 and len(data) >= 16:
        decoded = str(uuid.UUID(bytes_le=data[:16]))
    elif format_code == 4:
        decoded = [str(uuid.UUID(bytes_le=data[index : index + 16])) for index in range(0, len(data) - 15, 16)]
    elif format_code == 5:
        decoded = int.from_bytes(data[:8], "little")
    elif format_code == 6:
        decoded = bool(int.from_bytes(data[:8], "little"))
    elif format_code == 7:
        decoded = [int.from_bytes(data[index : index + 8], "little") for index in range(0, len(data) - 7, 8)]
    elif format_code == 1:
        strings = _utf16_strings(data)
        decoded = {"embedded_strings": strings}
    else:
        strings = _utf16_strings(data)
        decoded = {"size": len(data), "embedded_strings": strings}

    searchable: list[str]
    if isinstance(decoded, str):
        searchable = [decoded]
    elif isinstance(decoded, dict):
        searchable = [item for item in decoded.get("embedded_strings", []) if isinstance(item, str)]
    else:
        searchable = _utf16_strings(data)
    for text in searchable:
        for match in _BOOT_PATH.finditer(text):
            candidate = match.group().replace("\\", "/")
            # Strip Windows device annotations such as ramdisk=[boot] while
            # preserving the server-rooted portion used by TFTP/HTTP.
            slash = candidate.find("/")
            if slash >= 0:
                candidate = candidate[slash:]
            if candidate not in paths:
                paths.append(candidate)
    return format_name, decoded, paths


def decode_bcd(data: bytes) -> tuple[dict[str, Any], list[dict[str, str]]]:
    """Decode a Windows BCD hive and return JSON-safe details and boot paths."""
    hive = _Hive(data)
    root_name, values = hive.walk()
    objects: dict[str, list[dict[str, Any]]] = {}
    references: list[dict[str, str]] = []
    element_path = re.compile(
        r"(?i)(?:^|/)Objects/\{?([0-9a-f-]{36})\}?/Elements/([0-9a-f]{8})$"
    )
    for key_path, value in values:
        if value.name.lower() not in {"", "element"}:
            continue
        match = element_path.search(key_path)
        if not match:
            continue
        object_id = match.group(1).lower()
        element_id = int(match.group(2), 16)
        format_name, decoded, paths = _decode_element(element_id, value.data)
        element = {
            "id": f"0x{element_id:08x}",
            "name": _ELEMENT_NAMES.get(element_id, "unknown"),
            "format": format_name,
            "registry_type": value.data_type,
            "size": len(value.data),
            "value": decoded,
        }
        objects.setdefault(object_id, []).append(element)
        for path in paths:
            reference = {
                "path": path,
                "object": object_id,
                "element": f"0x{element_id:08x}",
                "element_name": element["name"],
            }
            if reference not in references:
                references.append(reference)

    decoded_objects: list[dict[str, Any]] = []
    for object_id, elements in sorted(objects.items()):
        description = next(
            (
                element["value"]
                for element in elements
                if element["id"] == "0x12000004" and isinstance(element["value"], str)
            ),
            None,
        )
        decoded_objects.append(
            {
                "id": object_id,
                "description": description,
                "elements": sorted(elements, key=lambda item: item["id"]),
            }
        )
    report = {
        "format": "Windows Boot Configuration Data registry hive",
        "root": root_name,
        "sequence_primary": hive.sequence_primary,
        "sequence_secondary": hive.sequence_secondary,
        "dirty": hive.sequence_primary != hive.sequence_secondary,
        "objects": decoded_objects,
        "references": references,
    }
    return report, references
