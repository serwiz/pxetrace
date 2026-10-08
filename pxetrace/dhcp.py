from __future__ import annotations

import fcntl
import hashlib
import random
import select
import socket
import struct
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable

from .models import DhcpReply
from .trace import Tracer

MAGIC_COOKIE = b"\x63\x82\x53\x63"
DHCP_DISCOVER = 1
DHCP_OFFER = 2
DHCP_REQUEST = 3
DHCP_ACK = 5
DHCP_NAK = 6
# wdsmgfw.efi stores the host-order constant 0x0001e240 directly in the
# network packet.  Interpreted as a big-endian DHCP field, its wire value is:
WDS_NBP_XID = 0x40E20100

ARCHITECTURES = {
    "bios-x86": 0,
    "uefi-ia32": 6,
    # IANA's corrected registry value used by actual x86-64 firmware.
    "uefi-x64": 7,
    "uefi-x64-rfc4578": 9,
    "uefi-arm32": 10,
    "uefi-arm64": 11,
}

OPTION_NAMES = {
    1: "subnet-mask",
    3: "routers",
    6: "dns-servers",
    12: "host-name",
    15: "domain-name",
    28: "broadcast-address",
    43: "vendor-encapsulated-options",
    50: "requested-address",
    51: "lease-time",
    52: "option-overload",
    53: "message-type",
    54: "server-identifier",
    55: "parameter-request-list",
    57: "maximum-message-size",
    58: "renewal-time",
    59: "rebinding-time",
    60: "vendor-class-identifier",
    61: "client-identifier",
    66: "tftp-server-name",
    67: "bootfile-name",
    77: "user-class",
    93: "client-system-architecture",
    94: "client-network-interface",
    97: "client-machine-identifier",
    243: "configmgr-boot-variables",
    250: "wds-nbp-options",
    252: "wds-bcd-file-path",
}


class DhcpError(RuntimeError):
    pass


@dataclass(slots=True)
class DhcpIdentity:
    mac: bytes
    arch: int
    machine_uuid: uuid.UUID
    vendor_class: str
    undi_major: int = 3
    undi_minor: int = 16
    hostname: str | None = None
    user_class: str | None = None


def parse_mac(value: str) -> bytes:
    compact = value.replace(":", "").replace("-", "")
    if len(compact) != 12:
        raise ValueError(f"adresse MAC invalide: {value!r}")
    try:
        result = bytes.fromhex(compact)
    except ValueError as exc:
        raise ValueError(f"adresse MAC invalide: {value!r}") from exc
    if result == b"\0" * 6 or result[0] & 1:
        raise ValueError("la MAC doit être une adresse unicast non nulle")
    return result


def format_mac(value: bytes) -> str:
    return ":".join(f"{octet:02x}" for octet in value)


def interface_mac(interface: str) -> bytes:
    active = interface_active_mac(interface)
    try:
        assignment_type = int((Path("/sys/class/net") / interface / "addr_assign_type").read_text().strip())
    except (OSError, ValueError):
        assignment_type = 0
    if assignment_type == 0:
        return active

    # systemd-udevd's net_id records the permanent hardware address even when
    # NetworkManager/systemd-networkd has replaced the active address.
    try:
        ifindex = (Path("/sys/class/net") / interface / "ifindex").read_text(encoding="ascii").strip()
        udev_data = (Path("/run/udev/data") / f"n{ifindex}").read_text(encoding="utf-8")
    except OSError:
        udev_data = ""
    for line in udev_data.splitlines():
        prefix = "E:ID_NET_NAME_MAC=enx"
        if line.startswith(prefix):
            candidate = line[len(prefix) :]
            if len(candidate) == 12:
                try:
                    return parse_mac(candidate)
                except ValueError:
                    pass
    return active


def interface_active_mac(interface: str) -> bytes:
    path = Path("/sys/class/net") / interface / "address"
    try:
        return parse_mac(path.read_text(encoding="ascii").strip())
    except OSError as exc:
        raise DhcpError(f"impossible de lire la MAC de {interface}: {exc}") from exc


def firmware_uuid() -> uuid.UUID:
    try:
        return uuid.UUID(Path("/sys/class/dmi/id/product_uuid").read_text(encoding="ascii").strip())
    except (OSError, ValueError):
        return uuid.UUID(int=(1 << 128) - 1)


def _option(code: int, value: bytes) -> bytes:
    if not 0 < code < 255 or len(value) > 255:
        raise ValueError("option DHCP hors limites")
    return bytes((code, len(value))) + value


def encode_options(options: Iterable[tuple[int, bytes]]) -> bytes:
    return MAGIC_COOKIE + b"".join(_option(code, value) for code, value in options) + b"\xff"


def internet_checksum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    words = struct.unpack(f"!{len(data) // 2}H", data)
    total = sum(words)
    total = (total & 0xFFFF) + (total >> 16)
    total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def raw_udp_broadcast(payload: bytes, source_port: int, destination_port: int, packet_id: int) -> bytes:
    """Build IPv4/UDP with source 0.0.0.0 as emitted before address assignment."""
    udp = struct.pack("!HHHH", source_port, destination_port, 8 + len(payload), 0) + payload
    source = socket.inet_aton("0.0.0.0")
    destination = socket.inet_aton("255.255.255.255")
    header_without_checksum = struct.pack(
        "!BBHHHBBH4s4s",
        0x45,
        0,
        20 + len(udp),
        packet_id & 0xFFFF,
        0,
        64,
        socket.IPPROTO_UDP,
        0,
        source,
        destination,
    )
    checksum = internet_checksum(header_without_checksum)
    ip_header = header_without_checksum[:10] + struct.pack("!H", checksum) + header_without_checksum[12:]
    return ip_header + udp


def decode_options(data: bytes) -> dict[int, bytes]:
    if not data.startswith(MAGIC_COOKIE):
        raise DhcpError("cookie DHCP absent ou invalide")
    result: dict[int, bytes] = {}
    offset = 4
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 0:
            continue
        if code == 255:
            break
        if offset >= len(data):
            raise DhcpError(f"option {code}: longueur absente")
        length = data[offset]
        offset += 1
        end = offset + length
        if end > len(data):
            raise DhcpError(f"option {code}: valeur tronquée")
        # RFC 3396 concatenation is useful for long vendor options.
        result[code] = result.get(code, b"") + data[offset:end]
        offset = end
    return result


def decode_pxe_vendor_options(data: bytes) -> list[dict[str, object]]:
    names = {
        1: "mtftp-ip",
        2: "mtftp-client-port",
        3: "mtftp-server-port",
        4: "mtftp-timeout",
        5: "mtftp-delay",
        6: "discovery-control",
        7: "discovery-multicast-address",
        8: "boot-server-list",
        9: "boot-menu",
        10: "menu-prompt",
        12: "credentials",
        71: "boot-item",
    }
    result: list[dict[str, object]] = []
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code in (0, 255):
            if code == 255:
                break
            continue
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1
        value = data[offset : offset + length]
        offset += length
        item: dict[str, object] = {
            "code": code,
            "name": names.get(code, f"suboption-{code}"),
            "hex": value.hex(),
        }
        if code == 6 and len(value) == 1:
            item["value"] = value[0]
            item["flags"] = {
                "disable-broadcast": bool(value[0] & 1),
                "disable-multicast": bool(value[0] & 2),
                "only-listed-servers": bool(value[0] & 4),
                "skip-discovery-if-filename-present": bool(value[0] & 8),
            }
        elif code == 10 and value:
            item["timeout"] = value[0]
            item["prompt"] = value[1:].decode("utf-8", "replace")
        elif code == 8:
            servers: list[dict[str, object]] = []
            inner = 0
            while inner + 3 <= len(value):
                server_type = struct.unpack("!H", value[inner : inner + 2])[0]
                count = value[inner + 2]
                inner += 3
                byte_count = count * 4
                if inner + byte_count > len(value):
                    break
                addresses = [
                    socket.inet_ntoa(value[pos : pos + 4])
                    for pos in range(inner, inner + byte_count, 4)
                ]
                inner += byte_count
                servers.append({"type": server_type, "addresses": addresses})
            item["servers"] = servers
        elif code == 71 and len(value) == 4:
            boot_type, layer = struct.unpack("!HH", value)
            item["boot_type"] = boot_type
            item["layer"] = layer
        result.append(item)
    return result


def build_packet(
    identity: DhcpIdentity,
    xid: int,
    *,
    message_type: int,
    requested_ip: str | None = None,
    server_id: str | None = None,
    ciaddr: str = "0.0.0.0",
    broadcast: bool = True,
    seconds_elapsed: int = 0,
    extra_options: Iterable[tuple[int, bytes]] = (),
) -> bytes:
    chaddr = identity.mac.ljust(16, b"\0")
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        6,
        0,
        xid,
        max(0, min(65535, seconds_elapsed)),
        0x8000 if broadcast else 0,
        socket.inet_aton(ciaddr),
        b"\0" * 4,
        b"\0" * 4,
        b"\0" * 4,
        chaddr,
        b"\0" * 64,
        b"\0" * 128,
    )
    options: list[tuple[int, bytes]] = [
        (53, bytes((message_type,))),
        (57, struct.pack("!H", 1472)),
        (60, identity.vendor_class.encode("ascii")),
        (93, struct.pack("!H", identity.arch)),
        (94, bytes((1, identity.undi_major, identity.undi_minor))),
        # PXE transports the SMBIOS UUID byte layout: the first three UUID
        # fields are little-endian, exactly as firmware exposes them.
        (97, b"\0" + identity.machine_uuid.bytes_le),
        (61, b"\x01" + identity.mac),
        (55, bytes((1, 3, 6, 15, 28, 43, 51, 54, 58, 59, 60, 66, 67, 93, 94, 97))),
    ]
    if identity.hostname:
        options.append((12, identity.hostname.encode("ascii", "replace")[:63]))
    if identity.user_class:
        encoded = identity.user_class.encode("ascii")
        # iPXE intentionally uses a plain string here (not RFC 3004's
        # length/value tuple) for compatibility with ISC dhcpd deployments.
        options.append((77, encoded))
    if requested_ip:
        options.append((50, socket.inet_aton(requested_ip)))
    if server_id:
        options.append((54, socket.inet_aton(server_id)))
    options.extend(extra_options)
    packet = header + encode_options(options)
    return packet.ljust(300, b"\0")


def build_wds_nbp_request(
    identity: DhcpIdentity,
    *,
    station_ip: str,
    server_ip: str,
    prompt_done: bool = False,
) -> bytes:
    """Build the DHCPREQUEST emitted by Microsoft's WDS UEFI boot manager.

    ``wdsmgfw.efi`` does not reuse the firmware DHCP request.  It sends this
    deliberately old-style request to UDP/4011.  In particular, the XID and
    elapsed-seconds fields are constants and option 250 is a private WDS NBP
    suboption stream.
    """
    xid = WDS_NBP_XID
    header = struct.pack(
        "!BBBBIHH4s4s4s4s16s64s128s",
        1,
        1,
        len(identity.mac),
        0,
        xid,
        0xFFFF,
        0,
        socket.inet_aton(station_ip),
        b"\0" * 4,
        socket.inet_aton(server_ip),
        b"\0" * 4,
        identity.mac.ljust(16, b"\0"),
        b"\0" * 64,
        b"\0" * 128,
    )
    # WDS NBP suboptions use one-byte type/length fields.  Values 12, 13,
    # 1 and 14 are emitted in this order by wdsmgfw.efi.  The trailing 0xff
    # terminates the private stream inside DHCP option 250.
    wds = (
        bytes((12, 1, int(prompt_done), 13, 2, 8, 0, 1, 2))
        + struct.pack("!H", identity.arch)
        + bytes((14, 1, 0, 255))
    )
    options: list[tuple[int, bytes]] = [
        (93, struct.pack("!H", identity.arch)),
        (97, b"\0" + identity.machine_uuid.bytes_le),
        (53, bytes((DHCP_REQUEST,))),
        (60, b"PXEClient"),
        (55, bytes((60, 128, 129, 130, 131, 132, 133, 134, 135))),
        (250, wds),
    ]
    return header + encode_options(options)


def decode_wds_nbp_options(data: bytes) -> list[dict[str, object]]:
    """Decode the byte-sized TLV stream carried by DHCP option 250."""
    names = {
        1: "architecture",
        2: "next-action",
        3: "poll-interval",
        4: "request-id",
        5: "referral-server",
        6: "message",
        11: "allow-server-selection",
        12: "prompt-done",
        13: "nbp-version",
        14: "action-done",
    }
    result: list[dict[str, object]] = []
    offset = 0
    while offset < len(data):
        code = data[offset]
        offset += 1
        if code == 255:
            break
        if code == 0:
            continue
        if offset >= len(data):
            break
        length = data[offset]
        offset += 1
        end = offset + length
        if end > len(data):
            break
        value = data[offset:end]
        offset = end
        item: dict[str, object] = {
            "code": code,
            "name": names.get(code, f"suboption-{code}"),
            "hex": value.hex(),
        }
        if code == 6:
            item["value"] = value.rstrip(b"\0").decode("utf-8", "replace")
        elif length == 1:
            item["value"] = value[0]
        elif length == 2:
            item["value"] = struct.unpack("!H", value)[0]
        elif code == 5 and length == 4:
            item["value"] = socket.inet_ntoa(value)
        result.append(item)
    return result


def wds_nbp_value(options: list[dict[str, object]], code: int) -> object | None:
    return next((item.get("value") for item in options if item.get("code") == code), None)


def decode_configmgr_boot_variables(data: bytes) -> dict[str, object]:
    """Decode the two ConfigMgr ProxyDHCP option-243 wire formats.

    Type 1 directly contains the media-variable path.  Type 2 contains the
    session-key structure followed by that path.  Secret material is never
    returned here; callers that need it use the original in-memory option.
    """
    result: dict[str, object] = {
        "size": len(data),
        "sha256": hashlib.sha256(data).hexdigest(),
    }
    if len(data) < 2:
        result["malformed"] = True
        return result
    packet_type, data_length = data[0], data[1]
    result["packet_type"] = packet_type
    result["password_protected"] = packet_type == 1
    if 2 + data_length > len(data):
        result["malformed"] = True
        return result
    if packet_type == 1:
        path_bytes = data[2 : 2 + data_length]
    elif packet_type == 2:
        result["session_key_available"] = True
        # One unknown byte separates the key structure from the length-prefixed
        # UTF-8 path in responses produced by ConfigMgr's TSPXE provider.
        length_index = 2 + data_length + 1
        if length_index >= len(data):
            result["malformed"] = True
            return result
        path_length = data[length_index]
        path_start = length_index + 1
        if path_start + path_length > len(data):
            result["malformed"] = True
            return result
        path_bytes = data[path_start : path_start + path_length]
    else:
        result["unsupported"] = True
        return result
    result["path"] = path_bytes.rstrip(b"\0").decode("utf-8", "replace")
    return result


def parse_reply(data: bytes, source: tuple[str, int], expected_xid: int, mac: bytes) -> DhcpReply:
    if len(data) < 240:
        raise DhcpError(f"paquet trop court ({len(data)} octets)")
    values = struct.unpack("!BBBBIHH4s4s4s4s16s64s128s", data[:236])
    op, _htype, hlen, _hops, xid, _secs, _flags = values[:7]
    if op != 2:
        raise DhcpError("le paquet n'est pas une BOOTREPLY")
    if xid != expected_xid:
        raise DhcpError("transaction DHCP différente")
    chaddr = values[11]
    if hlen != len(mac) or chaddr[:hlen] != mac:
        raise DhcpError("adresse matérielle différente")
    options = decode_options(data[236:])
    file_field = values[13]
    sname_field = values[12]
    overload_value = options.get(52, b"\0")
    if len(overload_value) != 1 or overload_value[0] not in {0, 1, 2, 3}:
        raise DhcpError("option 52 (surcharge) invalide")
    overload = overload_value[0]
    if overload & 1:
        for code, value in decode_options(MAGIC_COOKIE + file_field).items():
            options[code] = options.get(code, b"") + value
        boot_file = ""
    else:
        boot_file = file_field.split(b"\0", 1)[0].decode("utf-8", "replace")
    if overload & 2:
        for code, value in decode_options(MAGIC_COOKIE + sname_field).items():
            options[code] = options.get(code, b"") + value
        sname = ""
    else:
        sname = sname_field.split(b"\0", 1)[0].decode("utf-8", "replace")
    return DhcpReply(
        source_ip=source[0],
        source_port=source[1],
        xid=xid,
        yiaddr=socket.inet_ntoa(values[8]),
        siaddr=socket.inet_ntoa(values[9]),
        giaddr=socket.inet_ntoa(values[10]),
        sname=sname,
        boot_file=boot_file,
        options=options,
        received_at=time.monotonic(),
        raw_size=len(data),
        raw_hex=data.hex(),
    )


def describe_option(code: int, value: bytes) -> object:
    if code in {1, 28, 50, 54} and len(value) == 4:
        return socket.inet_ntoa(value)
    if code in {3, 6} and len(value) % 4 == 0:
        return [socket.inet_ntoa(value[i : i + 4]) for i in range(0, len(value), 4)]
    if code in {51, 58, 59} and len(value) == 4:
        return struct.unpack("!I", value)[0]
    if code == 53 and value:
        return {1: "DISCOVER", 2: "OFFER", 3: "REQUEST", 5: "ACK", 6: "NAK"}.get(value[0], value[0])
    if code == 93 and len(value) % 2 == 0:
        return list(struct.unpack(f"!{len(value) // 2}H", value))
    if code == 94 and len(value) == 3:
        return {"type": value[0], "major": value[1], "minor": value[2]}
    if code == 97 and len(value) == 17:
        return {"type": value[0], "uuid": str(uuid.UUID(bytes_le=value[1:]))}
    if code == 43:
        return decode_pxe_vendor_options(value)
    if code == 243:
        return decode_configmgr_boot_variables(value)
    if code == 250:
        return decode_wds_nbp_options(value)
    if code in {12, 15, 60, 66, 67, 252}:
        return value.rstrip(b"\0").decode("utf-8", "replace")
    if code == 77 and value:
        # Recognise RFC 3004 tuples, but preserve the de-facto raw string
        # emitted by iPXE and expected by most PXE configurations.
        classes: list[str] = []
        offset = 0
        while offset < len(value) and value[offset] <= len(value) - offset - 1:
            length = value[offset]
            offset += 1
            classes.append(value[offset : offset + length].decode("utf-8", "replace"))
            offset += length
        if offset == len(value) and classes:
            return classes
        return value.decode("utf-8", "replace")
    return value.hex()


def reply_as_dict(reply: DhcpReply) -> dict[str, object]:
    result: dict[str, object] = {
        "source": f"{reply.source_ip}:{reply.source_port}",
        "kind": "ProxyDHCP/PXE" if reply.is_proxy else "DHCP lease",
        "message_type": reply.message_type,
        "yiaddr": reply.yiaddr,
        "siaddr": reply.siaddr,
        "giaddr": reply.giaddr,
        "sname": reply.sname,
        "boot_file_field": reply.boot_file,
        "effective_boot_server": reply.effective_boot_server,
        "effective_boot_file": reply.effective_boot_file,
        "options": {
            f"{code}:{OPTION_NAMES.get(code, 'unknown')}": describe_option(code, value)
            for code, value in sorted(reply.options.items())
        },
    }
    if 243 in reply.options:
        result["raw_packet_sha256"] = hashlib.sha256(bytes.fromhex(reply.raw_hex)).hexdigest()
        result["raw_packet_redacted"] = "contient une clé de session ConfigMgr"
    else:
        result["raw_packet_hex"] = reply.raw_hex
    return result


class DhcpClient:
    def __init__(
        self,
        interface: str,
        identity: DhcpIdentity,
        tracer: Tracer,
        *,
        timeout: float = 4.0,
        attempts: int = 4,
        client_port: int = 68,
        server_port: int = 67,
        use_raw_broadcast: bool = True,
        require_pxe_offer: bool = True,
    ) -> None:
        self.interface = interface
        self.identity = identity
        self.tracer = tracer
        self.timeout = timeout
        self.attempts = attempts
        self.client_port = client_port
        self.server_port = server_port
        self.use_raw_broadcast = use_raw_broadcast
        self.require_pxe_offer = require_pxe_offer
        self._raw_fallback_reported = False

    def _socket(self) -> socket.socket:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode() + b"\0")
        try:
            sock.bind(("0.0.0.0", self.client_port))
        except PermissionError as exc:
            raise DhcpError(
                f"le port UDP {self.client_port} exige root ou CAP_NET_BIND_SERVICE"
            ) from exc
        except OSError as exc:
            raise DhcpError(
                f"impossible d'écouter 0.0.0.0:{self.client_port} sur {self.interface}: {exc}; "
                "un client DHCP système occupe peut-être déjà le port"
            ) from exc
        return sock

    def _send_broadcast(self, receiver: socket.socket, payload: bytes) -> None:
        if self.use_raw_broadcast:
            try:
                packet_id = random.SystemRandom().randrange(0, 65536)
                datagram = raw_udp_broadcast(payload, self.client_port, self.server_port, packet_id)
                with socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_UDP) as raw:
                    raw.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
                    raw.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                    if hasattr(socket, "SO_BINDTODEVICE"):
                        raw.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, self.interface.encode() + b"\0")
                    raw.sendto(datagram, ("255.255.255.255", self.server_port))
                self.tracer.emit(
                    "dhcp.transport",
                    "datagramme IPv4 brut émis avec source 0.0.0.0",
                    source=f"0.0.0.0:{self.client_port}",
                    destination=f"255.255.255.255:{self.server_port}",
                    ipv4_udp_hex=datagram.hex(),
                )
                return
            except OSError as exc:
                if not self._raw_fallback_reported:
                    self.tracer.emit(
                        "dhcp.transport",
                        "émission brute indisponible; repli sur UDP du noyau",
                        level="warning",
                        reason=str(exc),
                        consequence="l'adresse source IP peut être celle déjà configurée sur l'interface",
                    )
                    self._raw_fallback_reported = True
        receiver.sendto(payload, ("255.255.255.255", self.server_port))

    def exchange(self, *, commit_lease: bool = False) -> tuple[list[DhcpReply], DhcpReply | None]:
        xid = random.SystemRandom().randrange(1, 2**32)
        replies: list[DhcpReply] = []
        started = time.monotonic()
        with self._socket() as sock:
            seen: set[tuple[str, int, bytes]] = set()
            for attempt in range(self.attempts):
                window = self.timeout * (2**attempt)
                elapsed = round(time.monotonic() - started)
                packet = build_packet(
                    self.identity,
                    xid,
                    message_type=DHCP_DISCOVER,
                    seconds_elapsed=elapsed,
                )
                self.tracer.emit(
                    "dhcp.discover",
                    "envoi DHCPDISCOVER PXE en broadcast",
                    interface=self.interface,
                    source_port=self.client_port,
                    xid=f"0x{xid:08x}",
                    mac=format_mac(self.identity.mac),
                    arch=self.identity.arch,
                    vendor_class=self.identity.vendor_class,
                    user_class=self.identity.user_class,
                    attempt=attempt + 1,
                    wait_seconds=window,
                    secs_field=elapsed,
                    packet_hex=packet.hex(),
                )
                self._send_broadcast(sock, packet)
                deadline = time.monotonic() + window
                while True:
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        break
                    readable, _, _ = select.select([sock], [], [], remaining)
                    if not readable:
                        break
                    data, source = sock.recvfrom(65535)
                    try:
                        reply = parse_reply(data, source, xid, self.identity.mac)
                    except DhcpError as exc:
                        self.tracer.emit("dhcp.receive", "paquet ignoré", level="warning", reason=str(exc), source=source)
                        continue
                    # Do not discard a later response whose PXE options have
                    # changed while retaining the same BOOTP address fields.
                    key = (reply.source_ip, reply.source_port, data)
                    if key in seen:
                        continue
                    seen.add(key)
                    replies.append(reply)
                    self.tracer.emit(
                        "dhcp.offer",
                        "offre PXE reçue" if reply.is_proxy else "offre de bail reçue",
                        source=f"{source[0]}:{source[1]}",
                        yiaddr=reply.yiaddr,
                        siaddr=reply.siaddr,
                        boot_file=reply.effective_boot_file,
                        server=reply.effective_boot_server,
                        options={OPTION_NAMES.get(k, str(k)): describe_option(k, v) for k, v in reply.options.items()},
                    )
                    if not self.require_pxe_offer and not reply.is_proxy and reply.message_type == DHCP_OFFER:
                        break
                has_lease = any(not reply.is_proxy and reply.message_type == DHCP_OFFER for reply in replies)
                has_pxe = not self.require_pxe_offer or any(reply_has_pxe_service(reply) for reply in replies)
                if has_lease and has_pxe:
                    break
                if attempt + 1 < self.attempts:
                    self.tracer.emit(
                        "dhcp.retry",
                        "informations DHCP/PXE encore incomplètes",
                        level="warning",
                        lease_received=has_lease,
                        pxe_received=has_pxe,
                        next_attempt=attempt + 2,
                    )
            lease_offer = next((r for r in replies if not r.is_proxy and r.message_type == DHCP_OFFER), None)
            if not commit_lease or lease_offer is None:
                return replies, None
            server_id = lease_offer.server_identifier or lease_offer.source_ip
            for attempt in range(self.attempts):
                window = self.timeout * (2**attempt)
                request = build_packet(
                    self.identity,
                    xid,
                    message_type=DHCP_REQUEST,
                    requested_ip=lease_offer.yiaddr,
                    server_id=server_id,
                    seconds_elapsed=round(time.monotonic() - started),
                )
                self.tracer.emit(
                    "dhcp.request",
                    "envoi DHCPREQUEST pour reproduire la sélection du firmware",
                    requested_ip=lease_offer.yiaddr,
                    server_id=server_id,
                    attempt=attempt + 1,
                    wait_seconds=window,
                    packet_hex=request.hex(),
                )
                self._send_broadcast(sock, request)
                deadline = time.monotonic() + window
                lease_reply: DhcpReply | None = None
                while time.monotonic() < deadline:
                    readable, _, _ = select.select([sock], [], [], deadline - time.monotonic())
                    if not readable:
                        break
                    data, source = sock.recvfrom(65535)
                    try:
                        reply = parse_reply(data, source, xid, self.identity.mac)
                    except DhcpError:
                        continue
                    key = (reply.source_ip, reply.source_port, data)
                    if key in seen:
                        continue
                    seen.add(key)
                    if reply.is_proxy or reply_has_pxe_service(reply):
                        replies.append(reply)
                        self.tracer.emit(
                            "dhcp.proxy-reply",
                            "réponse PXE/ProxyDHCP reçue pendant la sélection du bail",
                            source=f"{source[0]}:{source[1]}",
                            message_type=reply.message_type,
                            boot_file=reply.effective_boot_file,
                            server=reply.effective_boot_server,
                            options={OPTION_NAMES.get(k, str(k)): describe_option(k, v) for k, v in reply.options.items()},
                        )
                    if reply.message_type in (DHCP_ACK, DHCP_NAK) and not reply.is_proxy:
                        if lease_reply is None:
                            lease_reply = reply
                            self.tracer.emit(
                                "dhcp.ack",
                                "bail confirmé" if reply.message_type == DHCP_ACK else "bail refusé",
                                level="info" if reply.message_type == DHCP_ACK else "error",
                                source=reply.source_ip,
                                yiaddr=reply.yiaddr,
                                attempt=attempt + 1,
                            )
                        if reply.message_type == DHCP_NAK:
                            return replies, reply
                if lease_reply is not None:
                    return replies, lease_reply
                if attempt + 1 < self.attempts:
                    self.tracer.emit(
                        "dhcp.request-retry",
                        "aucun DHCPACK, nouvelle tentative",
                        level="warning",
                        next_attempt=attempt + 2,
                    )
            self.tracer.emit("dhcp.ack", "aucun DHCPACK reçu", level="warning")
            return replies, None


def select_boot_offer(replies: list[DhcpReply]) -> tuple[DhcpReply | None, DhcpReply | None, list[str]]:
    diagnostics: list[str] = []
    lease = next((r for r in replies if not r.is_proxy and r.message_type == DHCP_ACK), None)
    if lease is None:
        lease = next((r for r in replies if not r.is_proxy and r.message_type == DHCP_OFFER), None)
    boot_candidates = [r for r in replies if r.effective_boot_file]

    def boot_rank(reply: DhcpReply) -> int:
        if reply.is_proxy and reply.message_type == DHCP_ACK:
            return 0  # Final response from PXE Boot Server discovery.
        if reply.is_proxy:
            return 1  # ProxyDHCP owns the PXE configuration.
        if reply.message_type == DHCP_ACK:
            return 2  # Authoritative configuration from the selected DHCP server.
        if reply.options.get(60, b"").startswith(b"PXEClient"):
            return 3
        return 4

    boot = min(boot_candidates, key=boot_rank) if boot_candidates else None
    if lease is None:
        diagnostics.append("aucune offre de bail IPv4")
    if boot is None:
        diagnostics.append("aucune offre ne fournit de fichier de démarrage (champ file ou option 67)")
    elif not boot.effective_boot_server:
        diagnostics.append("fichier fourni mais serveur absent (ni option 66 ni siaddr)")
    if lease and boot and lease is not boot:
        diagnostics.append("bail réseau et informations PXE fournis par deux réponses distinctes (ProxyDHCP)")
    return lease, boot, diagnostics


def interface_ipv4(interface: str) -> str:
    """Return the IPv4 address already configured on a Linux interface."""
    request = struct.pack("256s", interface.encode("ascii")[:15])
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            response = fcntl.ioctl(sock.fileno(), 0x8915, request)  # SIOCGIFADDR
    except OSError as exc:
        raise DhcpError(f"aucune adresse IPv4 utilisable sur {interface}: {exc}") from exc
    return socket.inet_ntoa(response[20:24])


def pxe_server_addresses(replies: list[DhcpReply], *, boot_type: int = 0) -> list[str]:
    """Extract unicast PXE boot-server candidates, preserving wire order."""
    result: list[str] = []
    for reply in replies:
        vendor_class = reply.options.get(60, b"")
        vendor = reply.options.get(43, b"")
        decoded = decode_pxe_vendor_options(vendor) if vendor else []
        only_listed = False
        for item in decoded:
            control = item.get("value")
            if item.get("code") == 6 and isinstance(control, int) and control & 4:
                only_listed = True
                break
        listed: list[str] = []
        for item in decoded:
            if item.get("code") == 8:
                server_groups = item.get("servers", [])
                if not isinstance(server_groups, list):
                    continue
                for group in server_groups:
                    if isinstance(group, dict) and group.get("type") == boot_type:
                        addresses = group.get("addresses", [])
                        if isinstance(addresses, list):
                            listed.extend(str(address) for address in addresses)
        if not only_listed and (reply.is_proxy or vendor_class.startswith(b"PXEClient")):
            result.append(reply.source_ip)
        result.extend(listed)
    return list(dict.fromkeys(address for address in result if address != "0.0.0.0"))


def reply_has_pxe_service(reply: DhcpReply) -> bool:
    """Distinguish an actual PXE reply from unrelated vendor option 43 data."""
    if reply.effective_boot_file or reply.source_port == 4011:
        return True
    if reply.options.get(60, b"").startswith(b"PXEClient"):
        return True
    vendor = reply.options.get(43, b"")
    if not vendor:
        return False
    # PXE 2.1-defined discovery/menu/boot-item suboptions. Unknown vendor
    # suboptions (for example Microsoft 241) are not evidence of PXE service.
    pxe_codes = {6, 7, 8, 9, 10, 71}
    return any(item.get("code") in pxe_codes for item in decode_pxe_vendor_options(vendor))


def query_pxe_boot_server(
    interface: str,
    identity: DhcpIdentity,
    tracer: Tracer,
    *,
    server: str,
    station_ip: str,
    timeout: float = 4.0,
    client_port: int = 68,
    boot_server_port: int = 4011,
    boot_type: int = 0,
    layer: int = 0,
) -> DhcpReply | None:
    """Perform the unicast PXE Boot Server Discover exchange on UDP/4011."""
    xid = random.SystemRandom().randrange(1, 2**32)
    # PXE option 43, suboption 71: boot server type (2) and layer (2).
    vendor_options = bytes((71, 4)) + struct.pack("!HH", boot_type, layer) + b"\xff"
    packet = build_packet(
        identity,
        xid,
        message_type=DHCP_REQUEST,
        ciaddr=station_ip,
        broadcast=False,
        extra_options=((43, vendor_options),),
    )
    tracer.emit(
        "pxe.discover",
        "requête unicast PXE Boot Server Discover",
        server=f"{server}:{boot_server_port}",
        station_ip=station_ip,
        source_port=client_port,
        boot_type=boot_type,
        layer=layer,
        xid=f"0x{xid:08x}",
        packet_hex=packet.hex(),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        try:
            sock.bind((station_ip, client_port))
        except PermissionError as exc:
            raise DhcpError(
                f"la découverte PXE nécessite le port UDP {client_port}; utilisez root ou CAP_NET_BIND_SERVICE"
            ) from exc
        except OSError as exc:
            raise DhcpError(
                f"impossible d'écouter {station_ip}:{client_port} pour la réponse PXE: {exc}"
            ) from exc
        sock.settimeout(timeout)
        last_error: str | None = None
        for attempt in range(1, 4):
            sock.sendto(packet, (server, boot_server_port))
            try:
                data, source = sock.recvfrom(65535)
            except socket.timeout:
                tracer.emit(
                    "pxe.retry",
                    "aucune réponse du Boot Server, retransmission",
                    level="warning",
                    server=server,
                    attempt=attempt,
                )
                continue
            try:
                reply = parse_reply(data, source, xid, identity.mac)
            except DhcpError as exc:
                last_error = str(exc)
                continue
            tracer.emit(
                "pxe.reply",
                "réponse du PXE Boot Server reçue",
                source=f"{source[0]}:{source[1]}",
                message_type=reply.message_type,
                siaddr=reply.siaddr,
                boot_file=reply.effective_boot_file,
                server=reply.effective_boot_server,
                options={OPTION_NAMES.get(k, str(k)): describe_option(k, v) for k, v in reply.options.items()},
            )
            return reply
        tracer.emit(
            "pxe.discover",
            "aucune réponse PXE Boot Server valide",
            level="warning",
            server=server,
            reason=last_error or "timeout",
        )
        return None


def query_wds_nbp(
    interface: str,
    identity: DhcpIdentity,
    tracer: Tracer,
    *,
    server: str,
    station_ip: str,
    timeout: float = 4.0,
    client_port: int = 68,
    boot_server_port: int = 4011,
    max_wait: float = 180.0,
) -> tuple[list[DhcpReply], DhcpReply | None]:
    """Run the post-``wdsmgfw.efi`` ConfigMgr/WDS exchange.

    ConfigMgr may answer with a temporary "looking for policy" status before
    generating the client-specific BCD.  Keep polling like the Microsoft NBP
    until option 252 appears or the bounded deadline expires.
    """
    try:
        server_ip = socket.gethostbyname(server)
    except OSError as exc:
        raise DhcpError(f"résolution du serveur WDS {server!r} impossible: {exc}") from exc
    packet = build_wds_nbp_request(identity, station_ip=station_ip, server_ip=server_ip)
    xid = WDS_NBP_XID
    replies: list[DhcpReply] = []
    deadline = time.monotonic() + max_wait
    attempt = 0
    last_status: str | None = None

    tracer.emit(
        "wds.request",
        "recherche de la configuration de démarrage",
        server=f"{server_ip}:{boot_server_port}",
        station_ip=station_ip,
        xid="0x0001e240",
        wire_xid=f"0x{xid:08x}",
        option_250=decode_wds_nbp_options(decode_options(packet[236:])[250]),
        packet_hex=packet.hex(),
    )
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        if hasattr(socket, "SO_BINDTODEVICE"):
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, interface.encode() + b"\0")
        try:
            sock.bind((station_ip, client_port))
        except PermissionError as exc:
            raise DhcpError(
                f"la requête WDS nécessite le port UDP {client_port}; utilisez root ou CAP_NET_BIND_SERVICE"
            ) from exc
        except OSError as exc:
            raise DhcpError(f"impossible d'écouter {station_ip}:{client_port} pour WDS: {exc}") from exc
        sock.settimeout(timeout)

        while time.monotonic() < deadline:
            attempt += 1
            sock.sendto(packet, (server_ip, boot_server_port))
            try:
                data, source = sock.recvfrom(65535)
            except socket.timeout:
                if attempt == 1 or attempt % 5 == 0:
                    tracer.emit(
                        "wds.retry",
                        "serveur toujours en attente, nouvelle tentative",
                        attempt=attempt,
                        server=server_ip,
                    )
                continue
            try:
                reply = parse_reply(data, source, xid, identity.mac)
            except DhcpError:
                continue
            replies.append(reply)
            bcd_path = reply.option_text(252)
            variables = decode_configmgr_boot_variables(reply.options[243]) if 243 in reply.options else {}
            wds_options = decode_wds_nbp_options(reply.options.get(250, b""))
            status = wds_nbp_value(wds_options, 6)
            tracer.emit(
                "wds.reply",
                "configuration de démarrage reçue" if bcd_path else "réponse intermédiaire reçue",
                source=f"{source[0]}:{source[1]}",
                boot_file=reply.effective_boot_file,
                bcd_path=bcd_path,
                variables_path=variables.get("path"),
                status=status,
                options={OPTION_NAMES.get(k, str(k)): describe_option(k, v) for k, v in reply.options.items()},
            )
            if bcd_path:
                return replies, reply

            status_text = str(status) if status else "le serveur prépare la politique PXE"
            poll_value = wds_nbp_value(wds_options, 3)
            poll_seconds = float(poll_value) if isinstance(poll_value, int) else timeout
            poll_seconds = max(1.0, min(30.0, poll_seconds))
            if status_text != last_status:
                tracer.emit(
                    "wds.wait",
                    status_text,
                    wait_seconds=poll_seconds,
                    attempt=attempt,
                )
                last_status = status_text
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(poll_seconds, remaining))

    tracer.emit(
        "wds.timeout",
        "aucun chemin BCD retourné avant expiration du délai",
        level="error",
        server=server_ip,
        wait_seconds=max_wait,
    )
    return replies, None
