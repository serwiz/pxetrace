from __future__ import annotations

import socket
import struct
import uuid

import pytest

from pxetrace.dhcp import (
    DHCP_ACK,
    DHCP_OFFER,
    DhcpError,
    DhcpIdentity,
    build_packet,
    build_wds_nbp_request,
    decode_configmgr_boot_variables,
    decode_options,
    decode_wds_nbp_options,
    describe_option,
    encode_options,
    interface_mac,
    internet_checksum,
    parse_reply,
    pxe_server_addresses,
    raw_udp_broadcast,
    reply_has_pxe_service,
    select_boot_offer,
)

MAC = bytes.fromhex("001122334455")


def reply_packet(
    xid: int,
    *,
    yiaddr: str = "0.0.0.0",
    siaddr: str = "0.0.0.0",
    filename: str = "",
    options: list[tuple[int, bytes]] | None = None,
) -> bytes:
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        2,
        1,
        6,
        0,
        xid,
        0,
        0x8000,
        b"\0" * 4,
        socket.inet_aton(yiaddr),
        socket.inet_aton(siaddr),
        b"\0" * 4,
        MAC.ljust(16, b"\0"),
        b"\0" * 64,
        filename.encode().ljust(128, b"\0"),
    )
    return header + encode_options(options or [(53, bytes((DHCP_OFFER,)))])


def test_discover_contains_firmware_identity() -> None:
    identity = DhcpIdentity(
        mac=MAC,
        arch=7,
        machine_uuid=uuid.UUID("00112233-4455-6677-8899-aabbccddeeff"),
        vendor_class="PXEClient:Arch:00007:UNDI:003016",
    )
    packet = build_packet(identity, 0x12345678, message_type=1)
    options = decode_options(packet[236:])
    assert options[53] == b"\x01"
    assert options[60] == b"PXEClient:Arch:00007:UNDI:003016"
    assert options[93] == b"\x00\x07"
    assert options[94] == b"\x01\x03\x10"
    assert options[97] == b"\0" + identity.machine_uuid.bytes_le
    assert options[61] == b"\x01" + MAC
    retried = build_packet(identity, 0x12345678, message_type=1, seconds_elapsed=19)
    unpacked = struct.unpack("!BBBBIHH", retried[:12])
    assert unpacked[3] == 0  # hops
    assert unpacked[5] == 19  # secs


def test_ipxe_user_class_uses_de_facto_raw_encoding() -> None:
    identity = DhcpIdentity(
        mac=MAC,
        arch=7,
        machine_uuid=uuid.UUID(int=0),
        vendor_class="PXEClient",
        user_class="iPXE",
    )
    packet = build_packet(identity, 1, message_type=1)
    options = decode_options(packet[236:])
    assert options[77] == b"iPXE"
    assert describe_option(77, options[77]) == "iPXE"


def test_wds_nbp_request_matches_wdsmgfw_wire_format() -> None:
    identity = DhcpIdentity(
        mac=MAC,
        arch=7,
        machine_uuid=uuid.UUID("00112233-4455-6677-8899-aabbccddeeff"),
        vendor_class="ignored-for-this-stage",
    )
    packet = build_wds_nbp_request(
        identity,
        station_ip="192.0.2.50",
        server_ip="192.0.2.20",
    )
    header = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", packet[:236])
    assert header[4:7] == (0x40E20100, 0xFFFF, 0)
    assert socket.inet_ntoa(header[7]) == "192.0.2.50"
    assert socket.inet_ntoa(header[9]) == "192.0.2.20"
    options = decode_options(packet[236:])
    assert options[53] == b"\x03"
    assert options[60] == b"PXEClient"
    assert options[55] == bytes((60, 128, 129, 130, 131, 132, 133, 134, 135))
    assert options[250] == bytes.fromhex("0c01000d020800010200070e0100ff")
    decoded = decode_wds_nbp_options(options[250])
    assert next(item["value"] for item in decoded if item["code"] == 1) == 7


def test_configmgr_option_243_exposes_variables_path() -> None:
    path = b"SMSTemp\\0000000008.var"
    option = bytes((1, len(path))) + path
    decoded = decode_configmgr_boot_variables(option)
    assert decoded["packet_type"] == 1
    assert decoded["password_protected"] is True
    assert decoded["path"] == path.decode()
    assert "hex" not in decoded


def test_configmgr_option_243_type_2_exposes_path_without_key_material() -> None:
    key_structure = bytes(range(48))
    path = b"SMSTemp\\0000000008.var"
    option = bytes((2, len(key_structure))) + key_structure + b"\x00" + bytes((len(path),)) + path
    decoded = decode_configmgr_boot_variables(option)
    assert decoded["packet_type"] == 2
    assert decoded["password_protected"] is False
    assert decoded["session_key_available"] is True
    assert decoded["path"] == path.decode()
    assert key_structure.hex() not in repr(decoded)


def test_normal_lease_and_proxy_offer_are_merged_by_selection() -> None:
    xid = 42
    lease = parse_reply(
        reply_packet(
            xid,
            yiaddr="192.0.2.50",
            options=[(53, b"\x02"), (54, socket.inet_aton("192.0.2.1"))],
        ),
        ("192.0.2.1", 67),
        xid,
        MAC,
    )
    proxy = parse_reply(
        reply_packet(
            xid,
            siaddr="192.0.2.20",
            filename="EFI/BOOT/bootx64.efi",
            options=[(53, b"\x02"), (60, b"PXEClient")],
        ),
        ("192.0.2.20", 67),
        xid,
        MAC,
    )
    selected_lease, selected_boot, diagnostics = select_boot_offer([lease, proxy])
    assert selected_lease is lease
    assert selected_boot is proxy
    assert selected_boot.effective_boot_server == "192.0.2.20"
    assert any("distinctes" in item for item in diagnostics)


def test_ack_is_the_authoritative_lease() -> None:
    offer = parse_reply(
        reply_packet(43, yiaddr="192.0.2.50", options=[(53, bytes((DHCP_OFFER,)))]),
        ("192.0.2.1", 67),
        43,
        MAC,
    )
    ack = parse_reply(
        reply_packet(43, yiaddr="192.0.2.50", options=[(53, bytes((DHCP_ACK,)))]),
        ("192.0.2.1", 67),
        43,
        MAC,
    )
    lease, _boot, _diagnostics = select_boot_offer([offer, ack])
    assert lease is ack


def test_proxy_ack_is_the_authoritative_boot_reply() -> None:
    offer = parse_reply(
        reply_packet(44, filename="first.efi", options=[(53, bytes((DHCP_OFFER,))), (60, b"PXEClient")]),
        ("192.0.2.20", 67),
        44,
        MAC,
    )
    ack = parse_reply(
        reply_packet(44, filename="selected.efi", options=[(53, bytes((DHCP_ACK,))), (60, b"PXEClient")]),
        ("192.0.2.20", 4011),
        44,
        MAC,
    )
    _lease, boot, _diagnostics = select_boot_offer([offer, ack])
    assert boot is ack


def test_option_67_overrides_bootp_file() -> None:
    packet = reply_packet(
        9,
        siaddr="192.0.2.20",
        filename="old.efi",
        options=[(53, b"\x02"), (67, b"new.efi")],
    )
    reply = parse_reply(packet, ("192.0.2.20", 67), 9, MAC)
    assert reply.effective_boot_file == "new.efi"


def test_invalid_option_overload_is_rejected() -> None:
    packet = reply_packet(10, options=[(53, b"\x02"), (52, b"")])
    with pytest.raises(DhcpError, match="option 52"):
        parse_reply(packet, ("192.0.2.20", 67), 10, MAC)


def test_pxe_boot_server_list_is_decoded() -> None:
    # PXE suboption 8: server type 0, two IPv4 addresses.
    server_list = struct.pack("!HB4s4s", 0, 2, socket.inet_aton("192.0.2.20"), socket.inet_aton("192.0.2.21"))
    vendor = bytes((8, len(server_list))) + server_list + b"\xff"
    packet = reply_packet(
        71,
        options=[(53, b"\x02"), (60, b"PXEClient"), (43, vendor)],
    )
    reply = parse_reply(packet, ("192.0.2.10", 67), 71, MAC)
    assert pxe_server_addresses([reply]) == ["192.0.2.10", "192.0.2.20", "192.0.2.21"]

    only_listed_vendor = bytes((6, 1, 4, 8, len(server_list))) + server_list + b"\xff"
    only_listed_packet = reply_packet(
        72,
        options=[(53, b"\x02"), (60, b"PXEClient"), (43, only_listed_vendor)],
    )
    only_listed = parse_reply(only_listed_packet, ("192.0.2.10", 67), 72, MAC)
    assert pxe_server_addresses([only_listed]) == ["192.0.2.20", "192.0.2.21"]


def test_unrelated_vendor_option_is_not_mistaken_for_pxe() -> None:
    unrelated = parse_reply(
        reply_packet(
            73,
            yiaddr="192.0.2.50",
            siaddr="192.0.2.250",
            options=[(53, b"\x02"), (43, bytes((241, 4)) + socket.inet_aton("192.0.2.99"))],
        ),
        ("192.0.2.1", 67),
        73,
        MAC,
    )
    assert reply_has_pxe_service(unrelated) is False
    assert pxe_server_addresses([unrelated]) == []

    pxe_vendor = bytes((6, 1, 0, 255))
    pxe = parse_reply(
        reply_packet(74, options=[(53, b"\x02"), (43, pxe_vendor)]),
        ("192.0.2.20", 67),
        74,
        MAC,
    )
    assert reply_has_pxe_service(pxe) is True


def test_permanent_mac_is_preferred_when_linux_changed_it(monkeypatch: pytest.MonkeyPatch) -> None:
    files = {
        "/sys/class/net/eth0/address": "5a:1a:56:54:02:a1\n",
        "/sys/class/net/eth0/addr_assign_type": "3\n",
        "/sys/class/net/eth0/ifindex": "7\n",
        "/run/udev/data/n7": "E:ID_NET_NAME_MAC=enxa029193050ae\n",
    }

    def fake_read_text(path, *args, **kwargs):
        return files[str(path)]

    monkeypatch.setattr("pxetrace.dhcp.Path.read_text", fake_read_text)
    assert interface_mac("eth0") == bytes.fromhex("a029193050ae")


def test_raw_dhcp_datagram_has_zero_source_and_valid_ip_checksum() -> None:
    payload = b"dhcp payload"
    datagram = raw_udp_broadcast(payload, 68, 67, 0x1234)
    assert datagram[12:16] == socket.inet_aton("0.0.0.0")
    assert datagram[16:20] == socket.inet_aton("255.255.255.255")
    assert internet_checksum(datagram[:20]) == 0
    source_port, destination_port, length, checksum = struct.unpack("!HHHH", datagram[20:28])
    assert (source_port, destination_port, length, checksum) == (68, 67, 8 + len(payload), 0)
    assert datagram[28:] == payload
