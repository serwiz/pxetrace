from __future__ import annotations

import struct
from pathlib import Path
from typing import ClassVar

from pxetrace.chain import (
    ChainTracer,
    binary_hints,
    detect_kind,
    parse_grub,
    parse_ipxe,
    parse_pxelinux,
    windows_boot_manager_hints,
)
from pxetrace.models import BootTarget
from pxetrace.trace import Tracer
from pxetrace.transfer import (
    Fetcher,
    FetchResult,
    TftpClient,
    _tftp_ack,
    _tftp_request,
    boot_uri,
    resolve_reference,
)


def test_ipxe_parser_resolves_relative_paths_and_known_variables() -> None:
    targets = parse_ipxe(
        "tftp://192.0.2.10/menu/main.ipxe",
        """#!ipxe
set base images
kernel ${base}/vmlinuz quiet
initrd ${next-server}/initrd.img
chain --autofree http://boot.example/other.ipxe
boot
""",
        {"next-server": "192.0.2.10"},
    )
    assert [item.uri for item in targets] == [
        "tftp://192.0.2.10/menu/images/vmlinuz",
        "tftp://192.0.2.10/menu/192.0.2.10/initrd.img",
        "http://boot.example/other.ipxe",
    ]


def test_grub_and_pxelinux_parsers() -> None:
    grub = parse_grub(
        "tftp://server/grub/grub.cfg",
        "linuxefi /images/vmlinuz root=/dev/nfs\ninitrdefi /images/initrd.img\n",
    )
    assert [item.kind for item in grub] == ["kernel", "initrd"]
    assert grub[0].uri == "tftp://server/images/vmlinuz"
    remote_grub = parse_grub(
        "tftp://server/grub/grub.cfg",
        "configfile (tftp,other.example)/menus/next.cfg\n",
    )
    assert remote_grub[0].uri == "tftp://other.example/menus/next.cfg"

    syslinux = parse_pxelinux(
        "tftp://server/pxelinux.cfg/default",
        "KERNEL ../vmlinuz\nAPPEND quiet initrd=../initrd.img,../ucode.img\n",
    )
    assert [item.uri for item in syslinux] == [
        "tftp://server/vmlinuz",
        "tftp://server/initrd.img",
        "tftp://server/ucode.img",
    ]


def test_destination_cannot_escape_output(tmp_path: Path) -> None:
    fetcher = Fetcher(tmp_path, Tracer())
    destination = fetcher.destination_for("tftp://server/../../etc/passwd")
    assert destination.is_relative_to(tmp_path.resolve())
    assert ".." not in destination.parts
    assert fetcher.destination_for("http://server:8080/a") != fetcher.destination_for("http://server:8081/a")
    assert fetcher.destination_for("tftp://server/a:b") != fetcher.destination_for("tftp://server/a*b")


def test_kind_detection_and_uri_helpers() -> None:
    assert detect_kind("tftp://server/boot.ipxe", b"#!ipxe\nboot\n") == "ipxe-script"
    assert detect_kind("tftp://server/bootx64.efi", b"MZ" + b"\0" * 20) == "uefi-pe"
    assert boot_uri("192.0.2.1", r"EFI\BOOT\bootx64.efi") == "tftp://192.0.2.1/EFI/BOOT/bootx64.efi"
    assert boot_uri("192.0.2.1", "/absolute.efi") == "tftp://192.0.2.1//absolute.efi"
    assert resolve_reference("tftp://server/a/menu.ipxe", "../kernel") == "tftp://server/kernel"


def test_windows_boot_artifacts_are_followed_without_global_heuristics() -> None:
    hints = binary_hints(
        "tftp://server/EFI/Microsoft/Boot/bootmgfw.efi",
        b"noise \\Boot\\BCD more \\sources\\boot.wim and helper.efi",
    )
    by_uri = {item.uri: item.certainty for item in hints}
    assert by_uri["tftp://server/Boot/BCD"] == "inferred"
    assert by_uri["tftp://server/sources/boot.wim"] == "inferred"
    assert by_uri["tftp://server/EFI/Microsoft/Boot/helper.efi"] == "heuristic"
    bare_bcd = binary_hints("tftp://server/smsboot/x64/wdsmgfw.efi", b"prefix BCD suffix")
    assert bare_bcd[0].uri == "tftp://server/smsboot/x64/BCD"
    assert bare_bcd[0].certainty == "heuristic"
    resource_wim = binary_hints("tftp://server/wdsmgfw.efi", b"windows/system32/tcbres.wim")
    assert resource_wim[0].certainty == "heuristic"
    implicit = windows_boot_manager_hints("tftp://server/EFI/Microsoft/Boot/bootmgfw.efi")
    assert implicit[0].uri == "tftp://server/EFI/Microsoft/Boot/BCD"
    assert implicit[0].certainty == "inferred"


def test_tftp_rrq_options_are_well_formed() -> None:
    fields = _tftp_request("boot.efi", 1468, 4)[2:].split(b"\0")
    assert fields == [
        b"boot.efi",
        b"octet",
        b"tsize",
        b"0",
        b"blksize",
        b"1468",
        b"windowsize",
        b"4",
        b"msftwindow",
        b"31416",
        b"",
    ]


def test_microsoft_variable_window_ack_has_next_window_byte() -> None:
    assert _tftp_ack(0x10000, 4, microsoft_window=True) == struct.pack("!HHB", 4, 0, 4)
    assert _tftp_ack(12, 4, microsoft_window=False) == struct.pack("!HH", 4, 12)


def test_tftp_oack_and_multiblock_transfer(monkeypatch, tmp_path: Path) -> None:
    peer = ("192.0.2.10", 49152)

    class FakeSocket:
        sent: ClassVar[list[tuple[bytes, tuple[str, int]]]] = []

        def __init__(self, *_args, **_kwargs) -> None:
            self.responses = [
                (
                    struct.pack("!H", 6)
                    + b"blksize\0"
                    + b"8\0"
                    + b"windowsize\0"
                    + b"2\0"
                    + b"msftwindow\0"
                    + b"27182\0"
                    + b"tsize\0"
                    + b"11\0",
                    peer,
                ),
                (struct.pack("!HH", 3, 1) + b"abcdefgh", peer),
                (struct.pack("!HH", 3, 2) + b"ijk", peer),
            ]

        def __enter__(self):
            return self

        def __exit__(self, *_args) -> None:
            return None

        def settimeout(self, _timeout: float) -> None:
            pass

        def sendto(self, data: bytes, target: tuple[str, int]) -> None:
            self.sent.append((data, target))

        def recvfrom(self, _size: int):
            return self.responses.pop(0)

    monkeypatch.setattr("pxetrace.transfer.socket.gethostbyname", lambda _host: "192.0.2.10")
    monkeypatch.setattr("pxetrace.transfer.socket.socket", FakeSocket)
    destination = tmp_path / "boot.bin"
    result = TftpClient(Tracer(), block_size=8).get("server", "boot%20file.bin", destination)
    assert result.size == 11
    assert result.sha256 is not None
    assert destination.read_bytes() == b"abcdefghijk"
    assert FakeSocket.sent[0][1] == ("192.0.2.10", 69)
    assert FakeSocket.sent[0][0][2:].split(b"\0", 1)[0] == b"boot file.bin"
    assert [packet for packet, _target in FakeSocket.sent[1:]] == [
        struct.pack("!HHB", 4, 0, 2),
        struct.pack("!HHB", 4, 2, 2),
    ]


def test_chain_file_limit_is_global_across_calls(tmp_path: Path) -> None:
    script = tmp_path / "menu.ipxe"
    script.write_text("#!ipxe\nchain one.ipxe\nchain two.ipxe\n", encoding="utf-8")

    class StaticFetcher:
        def __init__(self) -> None:
            self.calls: list[str] = []

        def fetch(self, uri: str):
            self.calls.append(uri)
            return FetchResult(script, script.stat().st_size, None)

    fetcher = StaticFetcher()
    tracer = ChainTracer(fetcher, Tracer(), max_files=1)  # type: ignore[arg-type]
    first = tracer.trace(BootTarget("tftp://server/menu.ipxe"))
    second = tracer.trace(BootTarget("tftp://server/three.ipxe"))
    assert fetcher.calls == ["tftp://server/menu.ipxe"]
    assert [item.status for item in first[1:]] == ["transfer-limit", "transfer-limit"]
    assert second[0].status == "transfer-limit"


def test_configmgr_variable_semantic_kind_survives_binary_detection(tmp_path: Path) -> None:
    variables = tmp_path / "media.var"
    variables.write_bytes(b"\x00\xff\x00\xff")

    class StaticFetcher:
        def fetch(self, _uri: str) -> FetchResult:
            return FetchResult(variables, variables.stat().st_size, None)

    target = BootTarget("tftp://server/SMSTemp/media.boot.var", kind="configmgr-variables")
    traced = ChainTracer(StaticFetcher(), Tracer()).trace(target)  # type: ignore[arg-type]

    assert traced[0].kind == "configmgr-variables"
    assert traced[0].metadata["detected_kind"] == "binary"
