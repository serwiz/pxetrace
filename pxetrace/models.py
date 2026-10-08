from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class TraceEvent:
    elapsed_ms: int
    phase: str
    level: str
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(slots=True)
class BootTarget:
    """A fetchable object in the reconstructed boot graph."""

    uri: str
    kind: str = "unknown"
    source: str = "dhcp"
    certainty: str = "certain"
    parent: str | None = None
    local_path: Path | None = None
    size_bytes: int | None = None
    sha256: str | None = None
    status: str = "pending"
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        result = asdict(self)
        if self.local_path is not None:
            result["local_path"] = str(self.local_path)
        return result


@dataclass(slots=True)
class DhcpReply:
    source_ip: str
    source_port: int
    xid: int
    yiaddr: str
    siaddr: str
    giaddr: str
    sname: str
    boot_file: str
    options: dict[int, bytes]
    received_at: float
    raw_size: int
    raw_hex: str

    @property
    def message_type(self) -> int | None:
        value = self.options.get(53, b"")
        return value[0] if value else None

    @property
    def server_identifier(self) -> str | None:
        import socket

        value = self.options.get(54)
        return socket.inet_ntoa(value) if value and len(value) == 4 else None

    @property
    def is_proxy(self) -> bool:
        return self.yiaddr == "0.0.0.0"

    def option_text(self, code: int) -> str | None:
        value = self.options.get(code)
        if not value:
            return None
        return value.rstrip(b"\0").decode("utf-8", "replace")

    @property
    def effective_boot_file(self) -> str | None:
        return self.option_text(67) or self.boot_file or None

    @property
    def effective_boot_server(self) -> str | None:
        return self.option_text(66) or (self.siaddr if self.siaddr != "0.0.0.0" else None)
