from __future__ import annotations

import struct
from pathlib import Path

from pxetrace.bcd import decode_bcd
from pxetrace.chain import ChainTracer
from pxetrace.models import BootTarget
from pxetrace.trace import Tracer
from pxetrace.transfer import FetchResult


def _minimal_bcd(path: str) -> bytes:
    hbin = bytearray(0x20)
    hbin[:4] = b"hbin"

    def cell(payload: bytes) -> int:
        offset = len(hbin)
        size = (len(payload) + 4 + 7) & ~7
        hbin.extend(struct.pack("<i", -size))
        hbin.extend(payload)
        hbin.extend(b"\0" * (size - 4 - len(payload)))
        return offset

    def key(name: str, children: list[int] | None = None, value: int | None = None) -> int:
        children = children or []
        child_list = cell(b"li" + struct.pack("<H", len(children)) + b"".join(struct.pack("<I", item) for item in children)) if children else 0xFFFFFFFF
        value_list = cell(struct.pack("<I", value)) if value is not None else 0xFFFFFFFF
        encoded = name.encode("latin-1")
        payload = bytearray(0x4C + len(encoded))
        payload[:2] = b"nk"
        struct.pack_into("<H", payload, 2, 0x20)
        struct.pack_into("<I", payload, 0x14, len(children))
        struct.pack_into("<I", payload, 0x1C, child_list)
        struct.pack_into("<I", payload, 0x24, 1 if value is not None else 0)
        struct.pack_into("<I", payload, 0x28, value_list)
        struct.pack_into("<H", payload, 0x48, len(encoded))
        payload[0x4C:] = encoded
        return cell(bytes(payload))

    raw_value = (path + "\0").encode("utf-16le")
    data_offset = cell(raw_value)
    value_payload = bytearray(0x14 + len("Element"))
    value_payload[:2] = b"vk"
    struct.pack_into("<H", value_payload, 2, len("Element"))
    struct.pack_into("<I", value_payload, 4, len(raw_value))
    struct.pack_into("<I", value_payload, 8, data_offset)
    struct.pack_into("<I", value_payload, 0x0C, 3)
    struct.pack_into("<H", value_payload, 0x10, 1)
    value_payload[0x14:] = b"Element"
    value_offset = cell(bytes(value_payload))

    element = key("32000004", value=value_offset)
    elements = key("Elements", [element])
    object_key = key("{7619dcc9-fafe-11d9-b411-000476eba25f}", [elements])
    objects = key("Objects", [object_key])
    root = key("BCD00000000", [objects])

    block_size = (len(hbin) + 0xFFF) & ~0xFFF
    hbin.extend(b"\0" * (block_size - len(hbin)))
    struct.pack_into("<I", hbin, 8, block_size)
    base = bytearray(0x1000)
    base[:4] = b"regf"
    struct.pack_into("<I", base, 4, 1)
    struct.pack_into("<I", base, 8, 1)
    struct.pack_into("<I", base, 0x24, root)
    return bytes(base + hbin)


def test_decode_bcd_exposes_elements_and_boot_paths() -> None:
    report, references = decode_bcd(_minimal_bcd(r"\Boot\boot.sdi"))
    assert report["root"] == "BCD00000000"
    assert report["dirty"] is False
    assert report["objects"][0]["elements"][0]["name"] == "ramdisk.sdi_path"
    assert report["objects"][0]["elements"][0]["value"] == r"\Boot\boot.sdi"
    assert references == [
        {
            "path": "/Boot/boot.sdi",
            "object": "7619dcc9-fafe-11d9-b411-000476eba25f",
            "element": "0x32000004",
            "element_name": "ramdisk.sdi_path",
        }
    ]


def test_chain_downloads_wim_referenced_by_bcd(tmp_path: Path) -> None:
    bcd_path = tmp_path / "BCD"
    bcd_path.write_bytes(_minimal_bcd(r"\sources\boot.wim"))
    wim_path = tmp_path / "boot.wim"
    wim_path.write_bytes(b"MSWIM\0\0\0")

    class StaticFetcher:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def fetch(self, uri: str) -> FetchResult:
            self.calls.append(uri)
            path = bcd_path if uri.endswith("/BCD") else wim_path
            return FetchResult(path, path.stat().st_size, None)

    fetcher = StaticFetcher()
    chain = ChainTracer(fetcher, Tracer()).trace(BootTarget("tftp://server/Boot/BCD"))  # type: ignore[arg-type]
    assert fetcher.calls == ["tftp://server/Boot/BCD", "tftp://server/sources/boot.wim"]
    assert chain[0].kind == "windows-bcd"
    assert chain[0].metadata["bcd"]["objects"]
    assert chain[1].kind == "windows-image"
    assert chain[1].status == "downloaded"
