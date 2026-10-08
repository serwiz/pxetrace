from __future__ import annotations

import hashlib
import os
import posixpath
import socket
import struct
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path, PurePosixPath

from .trace import Tracer


class TransferError(RuntimeError):
    pass


class TftpError(TransferError):
    pass


@dataclass(slots=True, frozen=True)
class FetchResult:
    path: Path
    size: int
    sha256: str | None
    from_cache: bool = False


def _tftp_request(
    filename: str,
    block_size: int,
    timeout: float,
    window_size: int = 4,
    *,
    microsoft_window: bool = True,
) -> bytes:
    del timeout  # The Microsoft boot client does not negotiate RFC 2349 timeout.
    options = (
        b"octet\0tsize\0"
        b"0\0blksize\0"
        + str(block_size).encode("ascii")
        + b"\0windowsize\0"
        + str(window_size).encode("ascii")
        + (b"\0msftwindow\0" + b"31416\0" if microsoft_window else b"\0")
    )
    return struct.pack("!H", 1) + filename.encode("utf-8") + b"\0" + options


def _tftp_ack(block: int, window_size: int, *, microsoft_window: bool) -> bytes:
    packet = struct.pack("!HH", 4, block & 0xFFFF)
    if microsoft_window:
        # WDS' variable-window extension appends the desired size of the next
        # window as one byte to every ACK, including ACK(0) after the OACK.
        packet += bytes((min(255, max(1, window_size)),))
    return packet


def _parse_oack(packet: bytes) -> dict[str, str]:
    fields = packet[2:].rstrip(b"\0").split(b"\0")
    if len(fields) % 2:
        raise TftpError("OACK TFTP mal formé")
    return {
        fields[index].decode("ascii", "replace").lower(): fields[index + 1].decode("ascii", "replace")
        for index in range(0, len(fields), 2)
    }


class TftpClient:
    def __init__(
        self,
        tracer: Tracer,
        *,
        timeout: float = 3.0,
        retries: int = 5,
        block_size: int = 1456,
        window_size: int = 4,
        max_bytes: int = 1024 * 1024 * 1024,
    ) -> None:
        if not 8 <= block_size <= 65464:
            raise ValueError("blksize TFTP doit être compris entre 8 et 65464")
        if not 1 <= window_size <= 65535:
            raise ValueError("windowsize TFTP doit être compris entre 1 et 65535")
        self.tracer = tracer
        self.timeout = timeout
        self.retries = retries
        self.block_size = block_size
        self.window_size = window_size
        self.max_bytes = max_bytes

    def get(self, host: str, filename: str, destination: Path, *, port: int = 69) -> FetchResult:
        filename = urllib.parse.unquote(filename).replace("\\", "/")
        # The first slash is the URI path delimiter. A doubled slash retains
        # one leading slash in the opaque TFTP filename.
        filename = filename.removeprefix("/")
        if not filename:
            raise TftpError("nom de fichier TFTP vide")
        if "\0" in filename:
            raise TftpError("le nom de fichier TFTP contient un octet NUL")
        try:
            server_ip = socket.gethostbyname(host)
        except OSError as exc:
            raise TftpError(f"résolution du serveur TFTP {host!r} impossible: {exc}") from exc
        request = _tftp_request(filename, self.block_size, self.timeout, self.window_size)
        destination.parent.mkdir(parents=True, exist_ok=True)
        temporary = destination.with_name(destination.name + ".part")
        self.tracer.emit(
            "tftp.rrq",
            "demande de lecture TFTP",
            server=server_ip,
            port=port,
            filename=filename,
            requested_blksize=self.block_size,
        )
        total = 0
        digest = hashlib.sha256()
        negotiated_block_size = 512
        negotiated_window_size = 1
        microsoft_window = False
        blocks_since_ack = 0
        expected_block = 1
        peer: tuple[str, int] | None = None
        last_sent = request
        target = (server_ip, port)
        started = time.monotonic()
        announced_size: int | None = None
        last_progress = started
        next_progress_bytes = 128 * 1024 * 1024
        next_progress_fraction = 0.1
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock, temporary.open("wb") as output:
                sock.settimeout(self.timeout)
                sock.sendto(request, target)
                failures = 0
                while True:
                    try:
                        packet, source = sock.recvfrom(65535)
                    except TimeoutError:
                        failures += 1
                        if failures > self.retries:
                            raise TftpError(
                                f"délai TFTP dépassé après {self.retries} retransmissions; "
                                f"dernier bloc attendu={expected_block}"
                            )
                        self.tracer.emit(
                            "tftp.retry",
                            "expiration du délai, retransmission",
                            level="warning",
                            attempt=failures,
                            expected_block=expected_block,
                        )
                        sock.sendto(last_sent, peer or target)
                        continue
                    if source[0] != server_ip:
                        continue
                    if peer is None:
                        peer = source
                        self.tracer.emit("tftp.connect", "TID serveur établi", peer=f"{source[0]}:{source[1]}")
                    elif source != peer:
                        # RFC 1350 error 5: unknown transfer ID.
                        sock.sendto(struct.pack("!HH", 5, 5) + b"Unknown transfer ID\0", source)
                        continue
                    failures = 0
                    if len(packet) < 2:
                        continue
                    opcode = struct.unpack("!H", packet[:2])[0]
                    if opcode == 5:
                        code = struct.unpack("!H", packet[2:4])[0] if len(packet) >= 4 else -1
                        message = packet[4:].split(b"\0", 1)[0].decode("utf-8", "replace")
                        raise TftpError(
                            f"erreur serveur TFTP {code}: {message} "
                            f"(octets={total}, bloc_attendu={expected_block}, "
                            f"bloc_fil={expected_block & 0xFFFF}, blksize={negotiated_block_size}, "
                            f"windowsize={negotiated_window_size})"
                        )
                    if opcode == 6:
                        if expected_block != 1 or total:
                            continue
                        options = _parse_oack(packet)
                        if "blksize" in options:
                            try:
                                negotiated_block_size = int(options["blksize"])
                            except ValueError as exc:
                                raise TftpError("blksize invalide dans OACK") from exc
                            if not 8 <= negotiated_block_size <= self.block_size:
                                raise TftpError(f"blksize OACK hors limites: {negotiated_block_size}")
                        if "tsize" in options:
                            try:
                                announced = int(options["tsize"])
                            except ValueError as exc:
                                raise TftpError("tsize invalide dans OACK") from exc
                            if announced < 0:
                                raise TftpError("tsize négatif dans OACK")
                            if announced > self.max_bytes:
                                raise TftpError(
                                    f"fichier annoncé à {announced} octets, limite fixée à {self.max_bytes}"
                                )
                            announced_size = announced
                        if "windowsize" in options:
                            try:
                                negotiated_window_size = int(options["windowsize"])
                            except ValueError as exc:
                                raise TftpError("windowsize invalide dans OACK") from exc
                            if not 1 <= negotiated_window_size <= self.window_size:
                                raise TftpError(f"windowsize OACK hors limites: {negotiated_window_size}")
                        if "msftwindow" in options:
                            if options["msftwindow"] != "27182":
                                raise TftpError(
                                    f"valeur msftwindow inconnue dans OACK: {options['msftwindow']!r}"
                                )
                            microsoft_window = True
                        self.tracer.emit("tftp.oack", "options négociées", **options)
                        last_sent = _tftp_ack(
                            0,
                            negotiated_window_size,
                            microsoft_window=microsoft_window,
                        )
                        sock.sendto(last_sent, peer)
                        continue
                    if opcode != 3 or len(packet) < 4:
                        continue
                    block = struct.unpack("!H", packet[2:4])[0]
                    expected_wire = expected_block & 0xFFFF
                    previous_wire = (expected_block - 1) & 0xFFFF
                    if block == previous_wire:
                        sock.sendto(
                            _tftp_ack(
                                block,
                                negotiated_window_size,
                                microsoft_window=microsoft_window,
                            ),
                            peer,
                        )
                        continue
                    if block != expected_wire:
                        continue
                    payload = packet[4:]
                    if len(payload) > negotiated_block_size:
                        raise TftpError(
                            f"bloc {block} trop grand ({len(payload)} > {negotiated_block_size} octets)"
                        )
                    total += len(payload)
                    if total > self.max_bytes:
                        raise TftpError(f"taille maximale dépassée ({self.max_bytes} octets)")
                    output.write(payload)
                    digest.update(payload)
                    now = time.monotonic()
                    reached_fraction = bool(
                        announced_size
                        and total / announced_size >= next_progress_fraction
                    )
                    if total >= next_progress_bytes or reached_fraction or now - last_progress >= 20:
                        self.tracer.emit(
                            "tftp.progress",
                            "transfert en cours",
                            bytes=total,
                            total_bytes=announced_size,
                            elapsed_ms=round((now - started) * 1000),
                        )
                        last_progress = now
                        while next_progress_bytes <= total:
                            next_progress_bytes += 128 * 1024 * 1024
                        if announced_size:
                            while next_progress_fraction <= total / announced_size:
                                next_progress_fraction += 0.1
                    blocks_since_ack += 1
                    final_block = len(payload) < negotiated_block_size
                    if blocks_since_ack >= negotiated_window_size or final_block:
                        last_sent = _tftp_ack(
                            block,
                            negotiated_window_size,
                            microsoft_window=microsoft_window,
                        )
                        sock.sendto(last_sent, peer)
                        blocks_since_ack = 0
                    expected_block += 1
                    if final_block:
                        break
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except Exception:
            temporary.unlink(missing_ok=True)
            raise
        self.tracer.emit(
            "tftp.done",
            "transfert terminé",
            bytes=total,
            blocks=expected_block - 1,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            destination=str(destination),
        )
        return FetchResult(destination, total, digest.hexdigest())


class Fetcher:
    def __init__(
        self,
        output_dir: Path,
        tracer: Tracer,
        *,
        timeout: float = 5.0,
        max_bytes: int = 1024 * 1024 * 1024,
        reuse_cache: bool = False,
    ) -> None:
        self.output_dir = output_dir.resolve()
        self.tracer = tracer
        self.timeout = timeout
        self.max_bytes = max_bytes
        self.reuse_cache = reuse_cache
        self.tftp = TftpClient(tracer, timeout=timeout, max_bytes=max_bytes)

    def destination_for(self, uri: str) -> Path:
        parsed = urllib.parse.urlsplit(uri)
        scheme = parsed.scheme.lower() or "tftp"
        host = parsed.hostname or "unknown-server"
        if parsed.port is not None:
            host += f"_{parsed.port}"
        decoded_path = urllib.parse.unquote(parsed.path).replace("\\", "/")
        raw_parts = PurePosixPath(decoded_path).parts
        parts = [part for part in raw_parts if part not in {"", "/", ".", ".."}]
        safe_parts = ["".join(c if c.isalnum() or c in "._-" else "_" for c in part) or "_" for part in parts]
        if not safe_parts:
            safe_parts = ["index"]
        path_was_changed = len(parts) != len([part for part in raw_parts if part not in {"", "/"}]) or any(
            original != safe for original, safe in zip(parts, safe_parts)
        )
        if parsed.query or path_was_changed:
            safe_parts[-1] += "." + hashlib.sha256(uri.encode()).hexdigest()[:10]
        return self.output_dir.joinpath(scheme, host, *safe_parts)

    def fetch(self, uri: str) -> FetchResult:
        parsed = urllib.parse.urlsplit(uri)
        scheme = parsed.scheme.lower()
        destination = self.destination_for(uri)
        if self.reuse_cache and destination.exists():
            size = destination.stat().st_size
            if size > self.max_bytes:
                raise TransferError(
                    f"objet en cache de {size} octets, limite fixée à {self.max_bytes}"
                )
            self.tracer.emit("fetch.cache", "objet déjà récupéré", uri=uri, path=str(destination), bytes=size)
            return FetchResult(destination, size, None, from_cache=True)
        if scheme == "tftp":
            if not parsed.hostname:
                raise TransferError(f"serveur absent dans l'URI {uri!r}")
            return self.tftp.get(parsed.hostname, parsed.path, destination, port=parsed.port or 69)
        if scheme not in {"http", "https"}:
            raise TransferError(f"protocole non pris en charge: {scheme or '(absent)'}")
        self.tracer.emit("http.get", "requête HTTP", uri=uri)
        request = urllib.request.Request(uri, headers={"User-Agent": "pxetrace/0.1 (PXE chain tracer)"})
        temporary = destination.with_name(destination.name + ".part")
        destination.parent.mkdir(parents=True, exist_ok=True)
        total = 0
        digest = hashlib.sha256()
        started = time.monotonic()
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response, temporary.open("wb") as output:
                announced = response.headers.get("Content-Length")
                if announced and int(announced) > self.max_bytes:
                    raise TransferError(f"Content-Length {announced} dépasse la limite {self.max_bytes}")
                while chunk := response.read(128 * 1024):
                    total += len(chunk)
                    if total > self.max_bytes:
                        raise TransferError(f"taille maximale dépassée ({self.max_bytes} octets)")
                    output.write(chunk)
                    digest.update(chunk)
            os.replace(temporary, destination)
            os.chmod(destination, 0o600)
        except (OSError, urllib.error.URLError, ValueError, TransferError) as exc:
            temporary.unlink(missing_ok=True)
            if isinstance(exc, TransferError):
                raise
            raise TransferError(f"échec HTTP pour {uri}: {exc}") from exc
        self.tracer.emit(
            "http.done",
            "transfert terminé",
            uri=uri,
            final_uri=response.geturl(),
            status=response.status,
            bytes=total,
            elapsed_ms=round((time.monotonic() - started) * 1000),
            destination=str(destination),
        )
        return FetchResult(destination, total, digest.hexdigest())


def boot_uri(server: str, filename: str) -> str:
    if urllib.parse.urlsplit(filename).scheme:
        return filename
    normalized = filename.replace("\\", "/")
    return f"tftp://{server}/{urllib.parse.quote(normalized, safe='/@:~!$&()*+,;=-._')}"


def resolve_reference(base_uri: str, reference: str) -> str:
    reference = reference.strip().strip('"\'').replace("\\", "/")
    if not reference:
        return ""
    parsed_reference = urllib.parse.urlsplit(reference)
    if parsed_reference.scheme:
        return reference
    parsed_base = urllib.parse.urlsplit(base_uri)
    if parsed_base.scheme.lower() == "tftp":
        if parsed_reference.netloc:
            return urllib.parse.urlunsplit(
                (parsed_base.scheme, parsed_reference.netloc, parsed_reference.path, parsed_reference.query, parsed_reference.fragment)
            )
        if parsed_reference.path.startswith("/"):
            path = posixpath.normpath(parsed_reference.path)
        else:
            parent = posixpath.dirname(parsed_base.path) or "/"
            path = posixpath.normpath(posixpath.join(parent, parsed_reference.path))
        if not path.startswith("/"):
            path = "/" + path
        return urllib.parse.urlunsplit(
            (parsed_base.scheme, parsed_base.netloc, path, parsed_reference.query, parsed_reference.fragment)
        )
    return urllib.parse.urljoin(base_uri, reference)
