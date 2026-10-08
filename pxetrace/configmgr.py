from __future__ import annotations

import base64
import binascii
import hashlib
import os
import re
import shutil
import ssl
import struct
import subprocess
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
import zlib
from dataclasses import dataclass
from datetime import UTC, datetime
from email import policy
from email.message import EmailMessage
from email.parser import BytesParser
from pathlib import Path
from typing import cast
from uuid import uuid4


class ConfigMgrError(RuntimeError):
    pass


class ConfigMgrDecryptionError(ConfigMgrError):
    """A failed local decoding step, not evidence of a server boot failure."""

    def __init__(self, message: str, *, stage: str) -> None:
        super().__init__(message)
        self.stage = stage


_TSPXE_KEY = bytes.fromhex("9f679c9b373a1f48824f378733de24e9")
# CryptoAPI ALG_ID values, not AES block sizes (all AES blocks are 16 bytes).
_AES_KEY_BYTES = {0x660E: 16, 0x660F: 24, 0x6610: 32}
_MAX_HTTP_RESPONSE = 64 * 1024 * 1024


def validate_variables_path(path: str) -> str:
    """Accept only a relative ConfigMgr variable-file path from option 243."""
    if not path or len(path) > 1024:
        raise ValueError("chemin vide ou trop long")
    try:
        decoded = urllib.parse.unquote(path, errors="strict")
    except UnicodeError as exc:
        raise ValueError("encodage du chemin invalide") from exc
    if any(ord(character) < 0x20 for character in decoded):
        raise ValueError("caractère de contrôle dans le chemin")
    normalized = decoded.replace("\\", "/").lstrip("/")
    parsed = urllib.parse.urlsplit(normalized)
    if parsed.scheme or parsed.netloc or parsed.query or parsed.fragment:
        raise ValueError("le chemin doit rester relatif au serveur WDS")
    segments = normalized.split("/")
    if not normalized or any(segment in {"", ".", ".."} for segment in segments):
        raise ValueError("segments de chemin non sûrs")
    if any(":" in segment for segment in segments):
        raise ValueError("lecteur ou flux de fichier interdit")
    if not segments[-1].lower().endswith((".var", ".dat")):
        raise ValueError("extension de fichier de variables inattendue")
    return normalized


def _cryptderivekey_material(password: bytes) -> bytes:
    """Reproduce the legacy CryptoAPI SHA-1 AES/3DES key expansion."""
    digest = hashlib.sha1(password).digest()
    ipad = bytes(byte ^ 0x36 for byte in digest) + b"\x36" * (64 - len(digest))
    opad = bytes(byte ^ 0x5C for byte in digest) + b"\x5c" * (64 - len(digest))
    return hashlib.sha1(ipad).digest() + hashlib.sha1(opad).digest()


def _aes_cbc_decrypt(ciphertext: bytes, key: bytes, *, algorithm: int) -> bytes:
    key_size = _AES_KEY_BYTES.get(algorithm)
    if key_size is None:
        raise ConfigMgrError("algorithme AES ConfigMgr non pris en charge")
    if len(key) < key_size:
        raise ConfigMgrError("clé AES ConfigMgr trop courte")
    executable = shutil.which("openssl")
    if executable is None:
        raise ConfigMgrError("openssl absent: déchiffrement ConfigMgr impossible")
    if not ciphertext or len(ciphertext) % 16:
        raise ConfigMgrError("flux AES ConfigMgr tronqué ou mal aligné")
    try:
        completed = subprocess.run(
            [
                executable,
                "enc",
                f"-aes-{key_size * 8}-cbc",
                "-d",
                "-K",
                key[:key_size].hex(),
                "-iv",
                "00" * 16,
                "-nopad",
            ],
            input=ciphertext,
            capture_output=True,
            check=False,
            timeout=60,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigMgrError("impossible d'exécuter le déchiffrement AES ConfigMgr") from exc
    if completed.returncode:
        raise ConfigMgrError("échec du déchiffrement AES des variables ConfigMgr")
    return completed.stdout


def recover_blank_media_password(option_243: bytes) -> bytes:
    """Recover the per-session media password carried by option 243 type 2."""
    if len(option_243) < 3 or option_243[0] != 2:
        raise ConfigMgrError("média PXE protégé par mot de passe ou option 243 incompatible")
    structure_length = option_243[1]
    structure = option_243[2 : 2 + structure_length]
    if len(structure) != structure_length or not structure:
        raise ConfigMgrError("structure de clé ConfigMgr tronquée")
    encrypted_length = structure[0]
    wrapped = structure[1 : 1 + encrypted_length]
    if len(wrapped) != encrypted_length or len(wrapped) < 20:
        raise ConfigMgrError("structure de clé ConfigMgr invalide")
    header_size, plaintext_size, ciphertext_size, algorithm, flags = struct.unpack_from("<5I", wrapped)
    if (
        (header_size, plaintext_size, ciphertext_size, flags) != (20, 10, 16, 0)
        or algorithm not in _AES_KEY_BYTES
    ):
        raise ConfigMgrDecryptionError(
            "enveloppe de clé de session ConfigMgr non prise en charge",
            stage="session-key-envelope",
        )
    if ciphertext_size > len(wrapped) - header_size:
        raise ConfigMgrError("clé de média ConfigMgr tronquée")
    ciphertext = wrapped[header_size : header_size + ciphertext_size]
    decrypted = _aes_cbc_decrypt(ciphertext, _cryptderivekey_material(_TSPXE_KEY), algorithm=algorithm)
    # TsPxe calls CryptDecrypt with Final=TRUE and checks the declared length.
    # Do not use random bytes from an unsuccessfully unwrapped key as a password.
    padding_size = ciphertext_size - plaintext_size
    if decrypted[plaintext_size:] != bytes((padding_size,)) * padding_size:
        raise ConfigMgrDecryptionError(
            "clé de session de l'option 243 non récupérée: contrôle de fin de bloc AES invalide "
            "(décodage non validé; panne serveur non démontrée)",
            stage="session-key-decryption",
        )
    raw = decrypted[:plaintext_size].split(b"\0", 1)[0]
    # The ten decrypted signed bytes are expanded to the twenty-byte value
    # consumed by CryptoAPI when deriving the media-file AES key.
    return b"".join(bytes((byte, 0xFF if byte & 0x80 else 0x00)) for byte in raw)


@dataclass(slots=True)
class MediaVariables:
    plaintext: bytes
    management_points: tuple[str, ...]
    site_code: str | None
    media_guid: str | None
    pfx: bytes | None

    def public_dict(self) -> dict[str, object]:
        return {
            "management_points": list(self.management_points),
            "site_code": self.site_code,
            "media_guid_present": self.media_guid is not None,
            "client_certificate_present": self.pfx is not None,
            "plaintext_persisted": False,
        }


def _variable_map(plaintext: bytes) -> dict[str, str]:
    try:
        text = plaintext.decode("utf-16le").rstrip("\x00\ufeff\uffff")
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, ValueError) as exc:
        raise ConfigMgrError("contenu XML des variables ConfigMgr invalide") from exc
    variables: dict[str, str] = {}
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1].lower() != "var":
            continue
        name = element.attrib.get("name")
        value = (element.text or "").strip()
        if name and value:
            variables[name] = value
    return variables


def _media_ciphertext(blob: bytes) -> tuple[bytes, int, int]:
    """Read the lengths and CryptoAPI algorithm from the media envelope."""
    if len(blob) < 24:
        raise ConfigMgrError("en-tête des variables ConfigMgr tronqué")
    magic, header_size, plaintext_size, encrypted_size, algorithm, reserved = struct.unpack_from("<6I", blob)
    if magic != 0xECED0000 or header_size != 20 or algorithm not in _AES_KEY_BYTES or reserved != 0:
        raise ConfigMgrError("en-tête des variables ConfigMgr incompatible")
    if not encrypted_size or encrypted_size % 16:
        raise ConfigMgrError("charge chiffrée ConfigMgr mal alignée")
    if encrypted_size > len(blob) - 24:
        raise ConfigMgrError("charge chiffrée ConfigMgr tronquée")
    if not plaintext_size or plaintext_size % 2 or not 1 <= encrypted_size - plaintext_size <= 16:
        raise ConfigMgrError("longueur du texte ConfigMgr invalide")
    return blob[24 : 24 + encrypted_size], plaintext_size, algorithm


def decrypt_media_variables(blob: bytes, option_243: bytes) -> MediaVariables:
    """Decrypt a downloaded ConfigMgr variables file without writing plaintext."""
    if len(blob) <= 32:
        raise ConfigMgrError("fichier de variables ConfigMgr trop court")
    encrypted, plaintext_size, algorithm = _media_ciphertext(blob)
    password = recover_blank_media_password(option_243)
    decrypted = _aes_cbc_decrypt(encrypted, _cryptderivekey_material(password), algorithm=algorithm)
    padding_size = len(encrypted) - plaintext_size
    if decrypted[plaintext_size:] != bytes((padding_size,)) * padding_size:
        raise ConfigMgrDecryptionError(
            "variables ConfigMgr non déchiffrées: contrôle de fin de bloc AES invalide "
            "(correspondance clé/fichier ou format à vérifier)",
            stage="variables-decryption",
        )
    plaintext = decrypted[:plaintext_size]
    try:
        text = plaintext.decode("utf-16le", "strict").rstrip("\x00\ufeff\uffff")
    except UnicodeDecodeError as exc:
        raise ConfigMgrDecryptionError(
            f"texte déchiffré ConfigMgr invalide à l'octet {exc.start}/{len(plaintext)} "
            "(clé de session ou format à vérifier)",
            stage="variables-text",
        ) from exc
    xml_bytes = text.encode("utf-16le")
    values = _variable_map(xml_bytes)
    folded_values = {name.casefold(): value for name, value in values.items()}
    management_points: list[str] = []
    for name in ("smstsmp", "_smstsmp", "smstslocationmps", "_smstslocationmps"):
        value = folded_values.get(name)
        if not value:
            continue
        for match in re.finditer(r"https?://[^\s;,<>]+", value, re.IGNORECASE):
            candidate = match.group().rstrip("/")
            parsed_candidate = urllib.parse.urlsplit(candidate)
            candidate = urllib.parse.urlunsplit(
                (parsed_candidate.scheme.lower(), parsed_candidate.netloc, parsed_candidate.path, "", "")
            )
            if candidate not in management_points:
                management_points.append(candidate)
    pfx: bytes | None = None
    encoded_pfx = folded_values.get("_smstsmediapfx")
    if encoded_pfx:
        try:
            pfx = bytes.fromhex(encoded_pfx)
        except ValueError as exc:
            raise ConfigMgrError("certificat PFX ConfigMgr mal encodé") from exc
    return MediaVariables(
        plaintext=xml_bytes,
        management_points=tuple(management_points),
        site_code=folded_values.get("_smstssitecode"),
        media_guid=folded_values.get("_smsmediaguid"),
        pfx=pfx,
    )


@dataclass(slots=True, frozen=True)
class ConfigMgrPolicy:
    category: str
    url: str
    payloads: tuple[bytes, ...]
    error: str | None = None
    error_stage: str | None = None


@dataclass(slots=True)
class ConfigMgrPolicyResult:
    management_point: str
    assignments: int
    policies: list[ConfigMgrPolicy]
    incomplete: list[str]


def _run_openssl(arguments: list[str], *, data: bytes = b"", timeout: int = 60) -> bytes:
    executable = shutil.which("openssl")
    if executable is None:
        raise ConfigMgrError("openssl absent")
    try:
        completed = subprocess.run(
            [executable, *arguments],
            input=data,
            capture_output=True,
            check=False,
            timeout=timeout,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ConfigMgrError("impossible d'exécuter l'opération cryptographique ConfigMgr") from exc
    if completed.returncode:
        diagnostic = completed.stderr.decode("utf-8", "replace").strip().splitlines()
        detail = " | ".join(diagnostic)[:1200] if diagnostic else "aucun détail fourni"
        raise ConfigMgrError(f"opération cryptographique ConfigMgr refusée ({detail})")
    return completed.stdout


def _write_private(path: Path, data: bytes) -> None:
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as stream:
        stream.write(data)


def _extract_pfx(pfx: bytes, password: str, directory: Path) -> tuple[Path, Path]:
    pfx_path = directory / "media.pfx"
    key_path = directory / "client.key"
    cert_path = directory / "client.crt"
    _write_private(pfx_path, pfx)
    password_input = password.encode("utf-8") + b"\n"
    key = _run_openssl(
        ["pkcs12", "-in", str(pfx_path), "-nocerts", "-nodes", "-passin", "fd:0"],
        data=password_input,
    )
    certificate = _run_openssl(
        ["pkcs12", "-in", str(pfx_path), "-clcerts", "-nokeys", "-passin", "fd:0"],
        data=password_input,
    )
    _write_private(key_path, key)
    _write_private(cert_path, certificate)
    return cert_path, key_path


def _sign(data: bytes, key_path: Path) -> str:
    # CryptoAPI's RSA signature bytes are little-endian; OpenSSL returns the
    # same mathematical signature in big-endian form.
    return _run_openssl(["dgst", "-sha256", "-sign", str(key_path)], data=data)[::-1].hex()


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.fragment
    ):
        raise ConfigMgrError("URL ConfigMgr non sûre ou invalide")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ConfigMgrError("port ConfigMgr invalide") from exc
    return parsed.scheme, parsed.hostname.lower().rstrip("."), port


class _SameOriginRedirect(urllib.request.HTTPRedirectHandler):
    def __init__(self, allowed_origin: tuple[str, str, int]) -> None:
        super().__init__()
        self.allowed_origin = allowed_origin

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[no-untyped-def]
        resolved = urllib.parse.urljoin(req.full_url, newurl)
        if _origin(resolved) != self.allowed_origin:
            raise ConfigMgrError("redirection ConfigMgr hors du Management Point refusée")
        return super().redirect_request(req, fp, code, msg, headers, resolved)


def _urlopen(
    request: urllib.request.Request,
    context: ssl.SSLContext | None,
    timeout: float,
    *,
    allowed_origin: tuple[str, str, int],
) -> tuple[bytes, str]:
    if _origin(request.full_url) != allowed_origin:
        raise ConfigMgrError("requête ConfigMgr hors du Management Point refusée")
    handlers: list[urllib.request.BaseHandler] = [_SameOriginRedirect(allowed_origin)]
    if context is not None:
        handlers.append(urllib.request.HTTPSHandler(context=context))
    opener = urllib.request.build_opener(*handlers)
    try:
        with opener.open(request, timeout=timeout) as response:
            body = response.read(_MAX_HTTP_RESPONSE + 1)
            if len(body) > _MAX_HTTP_RESPONSE:
                raise ConfigMgrError("réponse ConfigMgr supérieure à 64 Mio")
            return body, response.headers.get("Content-Type", "")
    except ConfigMgrError:
        raise
    except (OSError, urllib.error.URLError, urllib.error.HTTPError) as exc:
        raise ConfigMgrError(f"requête refusée: {exc}") from exc


def _xml_text(data: bytes) -> str:
    candidates = ("utf-8-sig", "utf-16", "utf-16le", "utf-16be")
    for encoding in candidates:
        try:
            text = data.decode(encoding).strip("\x00\ufeff\uffff \r\n\t")
        except UnicodeError:
            continue
        if text.startswith("<"):
            try:
                ET.fromstring(text)
            except (ET.ParseError, ValueError):
                continue
            return text
    raise ConfigMgrError("réponse XML ConfigMgr invalide")


def _multipart_parts(content_type: str, body: bytes) -> list[bytes]:
    message = cast(
        EmailMessage,
        BytesParser(policy=policy.default).parsebytes(
            f"Content-Type: {content_type}\r\nMIME-Version: 1.0\r\n\r\n".encode() + body
        ),
    )
    if not message.is_multipart():
        raise ConfigMgrError("réponse multipart ConfigMgr invalide")
    return [part.get_payload(decode=True) or b"" for part in message.iter_parts()]


def _policy_assignments(xml: str, management_point: str) -> list[tuple[str, str]]:
    try:
        root = ET.fromstring(xml)
    except ET.ParseError as exc:
        raise ConfigMgrError("liste de stratégies ConfigMgr invalide") from exc
    found: list[tuple[str, str]] = []
    seen: set[str] = set()
    for element in root.iter():
        if element.tag.rsplit("}", 1)[-1] != "Policy":
            continue
        location = next(
            (
                child.text
                for child in element
                if child.tag.rsplit("}", 1)[-1] == "PolicyLocation" and child.text
            ),
            None,
        )
        if not location:
            continue
        substituted = location.replace("http://<mp>", management_point).replace(
            "https://<mp>", management_point
        )
        url = urllib.parse.urljoin(management_point + "/", substituted)
        if url in seen:
            continue
        seen.add(url)
        category = element.attrib.get("PolicyCategory") or element.attrib.get("PolicyID") or "Policy"
        found.append((category, url))
    return found


def _decrypt_cms(data: bytes, cert_path: Path, key_path: Path) -> bytes:
    """Use CMS algorithm parameters as encoded by the sender, without guessing."""
    candidates: list[tuple[str, bytes]] = []
    stripped = data.strip()
    if stripped.startswith(b"-----BEGIN"):
        candidates.append(("PEM", stripped))
    elif stripped.lower().startswith((b"mime-version:", b"content-type:")):
        candidates.append(("SMIME", data))
    else:
        candidates.append(("DER", data))
        # Only accept a whole base64 transport, never random offsets in ciphertext.
        try:
            decoded = base64.b64decode(b"".join(data.split()), validate=True)
            if decoded.startswith(b"\x30"):
                candidates.append(("DER", decoded))
        except (ValueError, binascii.Error):
            pass

    parsed = False
    errors: list[str] = []
    for encoding, candidate in candidates:
        try:
            _run_openssl(["cms", "-cmsout", "-noout", "-inform", encoding], data=candidate)
        except ConfigMgrError:
            continue
        parsed = True
        # OpenSSL reads RSA padding, OAEP hashes and content cipher from CMS.
        # Without -recip it can try the supplied key on recipient records whose
        # issuer/serial identifier differs (e.g. certificate renewal with same key).
        recipients: list[list[str]] = [["-recip", str(cert_path)], []]
        for recipient in recipients:
            try:
                plaintext = _run_openssl(
                    ["cms", "-decrypt", "-binary", "-inform", encoding,
                     "-inkey", str(key_path), *recipient], data=candidate,
                )
            except ConfigMgrError as exc:
                errors.append(str(exc))
                continue
            # A zero return code or nonempty binary output is not a valid policy.
            try:
                return _xml_text(plaintext).encode("utf-8")
            except ConfigMgrError as exc:
                raise ConfigMgrDecryptionError(
                    "CMS déchiffré, mais contenu XML de stratégie invalide",
                    stage="cms-plaintext",
                ) from exc
    if not parsed:
        raise ConfigMgrDecryptionError(
            "enveloppe CMS non reconnue ou tronquée (DER, PEM ou S/MIME attendu)",
            stage="cms-envelope",
        )
    detail = next((error for error in errors if "unsupported" in error.lower()), "")
    if detail:
        raise ConfigMgrDecryptionError(
            "algorithme CMS indisponible dans OpenSSL: " + detail, stage="cms-algorithm",
        )
    raise ConfigMgrDecryptionError(
        "enveloppe CMS reconnue; déchiffrement refusé avec la clé du média "
        "(destinataire, clé ou intégrité du contenu à vérifier)",
        stage="cms-recipient",
    )


def _des3_deobfuscate(value: str) -> bytes | None:
    compact = "".join(value.split())
    if len(compact) < 144 or len(compact) % 2 or any(char not in "0123456789abcdefABCDEF" for char in compact):
        return None
    try:
        key_data = bytes.fromhex(compact[8:88])
        encrypted = bytes.fromhex(compact[128:])
    except ValueError:
        return None
    if not encrypted or len(encrypted) % 8:
        return None
    try:
        plaintext = _run_openssl(
            [
                "enc",
                "-des-ede3-cbc",
                "-d",
                "-K",
                _cryptderivekey_material(key_data)[:24].hex(),
                "-iv",
                "00" * 8,
            ],
            data=encrypted,
        )
        # CryptDecrypt(Final=TRUE) uses PKCS#7. Reject padding errors and
        # nontext before treating any decoded bytes as evidence.
        text = plaintext.decode("utf-16le", "strict").rstrip("\x00")
        if any(not char.isprintable() and char not in "\r\n\t" for char in text):
            return None
        return text.encode("utf-8")
    except (ConfigMgrError, UnicodeError):
        return None


def _zlib_decompress_limited(data: bytes, max_output: int) -> bytes:
    if max_output < 1:
        raise ConfigMgrError("limite de décompression ConfigMgr atteinte")
    decompressor = zlib.decompressobj()
    try:
        output = decompressor.decompress(data, max_output + 1)
        if len(output) > max_output or decompressor.unconsumed_tail:
            raise ConfigMgrError("données ConfigMgr décompressées hors limites")
        output += decompressor.flush(max_output - len(output) + 1)
    except zlib.error as exc:
        raise ConfigMgrError("données ConfigMgr non décompressables") from exc
    if len(output) > max_output or not decompressor.eof:
        raise ConfigMgrError("données ConfigMgr décompressées hors limites")
    return output


def expand_policy_payload(data: bytes, *, max_total_bytes: int = 128 * 1024 * 1024) -> tuple[bytes, ...]:
    """Expand compressed XML and explicitly identified secret fields."""
    if len(data) > max_total_bytes:
        raise ConfigMgrError("stratégie ConfigMgr supérieure à la limite décompressée")
    expanded: list[bytes] = [data]
    queue: list[tuple[bytes, int]] = [(data, 0)]
    total = len(data)
    seen = {hashlib.sha256(data).digest()}
    while queue:
        current, depth = queue.pop(0)
        try:
            root = ET.fromstring(_xml_text(current))
        except (ConfigMgrError, ET.ParseError):
            continue
        parents = {child: node for node in root.iter() for child in node}
        candidates: list[bytes] = []
        changed = False
        for element in root.iter():
            value = (element.text or "").strip()
            if not value:
                continue
            compact = "".join(value.split())
            raw = b""
            if len(compact) >= 16 and len(compact) % 2 == 0:
                try:
                    raw = bytes.fromhex(compact)
                except ValueError:
                    pass
            # A zlib stream has a DEFLATE method and a valid CMF/FLG checksum.
            if len(raw) >= 2 and raw[0] & 15 == 8 and (raw[0] << 8 | raw[1]) % 31 == 0:
                candidates.append(_zlib_decompress_limited(raw, max_total_bytes - total))
                continue
            parent = parents.get(element)
            owner = element if element.get("secret") == "1" else parent
            marked = owner is not None and owner.get("secret") == "1"
            grandparent = parents.get(parent) if parent is not None else None
            collection = (
                parent is not None and parent.get("name") in {"Name", "Value"}
                and grandparent is not None
                and grandparent.get("class", "").casefold() == "ccm_collectionvariable"
                and len(raw) >= 72
            )
            if marked or collection:
                deobfuscated = _des3_deobfuscate(value)
                if deobfuscated is None:
                    name = owner.get("name", "inconnu") if owner is not None else "inconnu"
                    raise ConfigMgrError("champ secret ConfigMgr non décodé: " + name)
                element.text = deobfuscated.decode("utf-8")
                if owner is not None:
                    owner.set("secret", "0")
                changed = True
                if deobfuscated.lstrip().startswith(b"<"):
                    candidates.append(deobfuscated)
        if changed:
            candidates.append(ET.tostring(root, encoding="utf-8"))
        for candidate in candidates:
            digest = hashlib.sha256(candidate).digest()
            if digest in seen:
                continue
            if depth >= 8:
                raise ConfigMgrError("profondeur de décodage ConfigMgr dépassée")
            if total + len(candidate) > max_total_bytes:
                raise ConfigMgrError("volume décompressé de la stratégie hors limites")
            seen.add(digest)
            total += len(candidate)
            expanded.append(candidate)
            queue.append((candidate, depth + 1))
    return tuple(expanded)


def audit_management_point(
    media: MediaVariables,
    *,
    timeout: float = 10.0,
    max_policies: int = 1024,
    max_total_bytes: int = 256 * 1024 * 1024,
    max_duration: float = 300.0,
    diagnostic_directory: Path | None = None,
) -> ConfigMgrPolicyResult:
    """Read every policy assigned to the PXE media identity, without persisting plaintext."""
    if timeout <= 0 or max_policies < 1 or max_total_bytes < 1 or max_duration <= 0:
        raise ValueError("limites ConfigMgr invalides")
    if not media.management_points:
        raise ConfigMgrError("aucun Management Point dans les variables du média")
    if not media.media_guid or not media.pfx:
        raise ConfigMgrError("identité ou certificat de média ConfigMgr absent")
    management_point = media.management_points[0].rstrip("/")
    parsed = urllib.parse.urlsplit(management_point)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname or parsed.username:
        raise ConfigMgrError("URL de Management Point non sûre ou invalide")
    allowed_origin = _origin(management_point)
    deadline = time.monotonic() + max_duration

    def request_timeout() -> float:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise ConfigMgrError("durée maximale du contrôle ConfigMgr dépassée")
        return min(timeout, remaining)

    with tempfile.TemporaryDirectory(prefix="pxetrace-configmgr-") as temporary:
        certificate, key = _extract_pfx(media.pfx, media.media_guid[:31], Path(temporary))
        context: ssl.SSLContext | None = None
        if parsed.scheme == "https":
            context = ssl.create_default_context()
            context.load_cert_chain(certificate, key)
        info_request = urllib.request.Request(
            management_point + "/SMS_MP/.sms_aut?MPKEYINFORMATIONMEDIA",
            headers={"User-Agent": "pxetrace/0.1"},
        )
        info_body, _ = _urlopen(
            info_request,
            context,
            request_timeout(),
            allowed_origin=allowed_origin,
        )
        try:
            info_root = ET.fromstring(_xml_text(info_body))
        except ET.ParseError as exc:
            raise ConfigMgrError("MPKEYINFORMATIONMEDIA invalide") from exc
        unknown = next((node for node in info_root.iter() if node.tag.rsplit("}", 1)[-1] == "UnknownMachines"), None)
        site = next((node.text for node in info_root.iter() if node.tag.rsplit("}", 1)[-1] == "SITECODE"), None)
        client_id = None if unknown is None else (
            unknown.get("x64UnknownMachineGUID") or unknown.get("x86UnknownMachineGUID")
        )
        if not client_id or not site:
            raise ConfigMgrError("identité Unknown Computer ou code site absent du MP")

        timestamp = datetime.now(UTC).replace(microsecond=0).isoformat().replace("+00:00", "Z")
        media_id = media.media_guid
        token_signature = _sign((media_id + ";" + timestamp + "\0").encode("utf-16le"), key)
        message = (
            "<Msg><ID/><SourceID>" + client_id + "</SourceID><ReplyTo>direct:OSD</ReplyTo>"
            '<Body Type="ByteRange" Offset="0" Length="728"/><Hooks><Hook2 Name="clientauth">'
            '<Property Name="Token"><![CDATA[ClientToken:' + media_id + ";" + timestamp
            + "\r\nClientTokenSignature:" + token_signature
            + "\r\n]]></Property></Hook2></Hooks><Payload Type=\"inline\"/>"
            "<TargetEndpoint>MP_PolicyManager</TargetEndpoint><ReplyMode>Sync</ReplyMode></Msg>"
        )
        first = b"\xff\xfe" + message.encode("utf-16le")
        second = (
            '<RequestAssignments SchemaVersion="1.00" RequestType="Always" Ack="False" '
            'ValidationRequested="CRC"><PolicySource>SMS:' + site
            + '</PolicySource><ServerCookie/><Resource ResourceType="Machine"/><Identification><Machine><ClientID>'
            + client_id
            + '</ClientID><NetBIOSName></NetBIOSName><FQDN></FQDN><SID/></Machine></Identification>'
            '</RequestAssignments>\r\n'
        ).encode("utf-16le") + b"\0\0\0"
        boundary = "----pxetrace-" + uuid4().hex
        body = b""
        for name, payload in (("Msg", first), ("RequestAssignments", second)):
            body += (
                f"--{boundary}\r\nContent-Disposition: form-data; name=\"{name}\"\r\n"
                "Content-Type: text/plain; charset=UTF-16\r\n\r\n"
            ).encode() + payload + b"\r\n"
        body += f"--{boundary}--\r\n".encode()
        assignment_request = urllib.request.Request(
            management_point + "/ccm_system/request",
            data=body,
            method="CCM_POST",
            headers={"Content-Type": f"multipart/mixed; boundary={boundary}", "User-Agent": "pxetrace/0.1"},
        )
        assignment_body, content_type = _urlopen(
            assignment_request,
            context,
            request_timeout(),
            allowed_origin=allowed_origin,
        )
        parts = _multipart_parts(content_type, assignment_body)
        if len(parts) < 2:
            raise ConfigMgrError("réponse d'affectation ConfigMgr incomplète")
        try:
            assignment_xml = _xml_text(_zlib_decompress_limited(parts[1], _MAX_HTTP_RESPONSE))
        except ConfigMgrError as exc:
            raise ConfigMgrError("affectations ConfigMgr non décompressables ou hors limites") from exc
        all_assignments = _policy_assignments(assignment_xml, management_point)
        assignments = all_assignments[:max_policies]
        headers = {
            "CCMClientID": media_id,
            "CCMClientIDSignature": _sign((media_id + "\0").encode("utf-16le"), key),
            "CCMClientTimestamp": timestamp,
            "CCMClientTimestampSignature": _sign((timestamp + "\0").encode("utf-16le"), key),
            "User-Agent": "pxetrace/0.1",
        }
        policies: list[ConfigMgrPolicy] = []
        incomplete: list[str] = []
        if len(all_assignments) > max_policies:
            incomplete.append(
                f"limite de {max_policies} stratégies atteinte sur {len(all_assignments)} affectations"
            )
        expanded_bytes = 0
        for number, (category, url) in enumerate(assignments, 1):
            error_stage = "téléchargement HTTP"
            raw = b""
            try:
                raw, _ = _urlopen(
                    urllib.request.Request(url, headers=headers),
                    context,
                    request_timeout(),
                    allowed_origin=allowed_origin,
                )
                error_stage = "décodage XML/CMS"
                try:
                    plaintext = _xml_text(raw).encode("utf-8")
                except ConfigMgrError:
                    plaintext = _decrypt_cms(raw, certificate, key)
                error_stage = "décompression de la stratégie"
                payloads = expand_policy_payload(
                    plaintext,
                    max_total_bytes=max_total_bytes - expanded_bytes,
                )
                payload_bytes = sum(len(payload) for payload in payloads)
                if expanded_bytes + payload_bytes > max_total_bytes:
                    raise ConfigMgrError(
                        f"volume cumulé des stratégies supérieur à {max_total_bytes} octets"
                    )
                expanded_bytes += payload_bytes
                policies.append(ConfigMgrPolicy(category, url, payloads))
            except ConfigMgrError as exc:
                reason = str(exc)
                if isinstance(exc, ConfigMgrDecryptionError):
                    error_stage = exc.stage
                if raw:
                    reason += f" [réponse: {len(raw)} octets; SHA-256 {hashlib.sha256(raw).hexdigest()}]"
                    if diagnostic_directory is not None:
                        try:
                            diagnostic_directory.mkdir(mode=0o700, parents=True, exist_ok=True)
                            saved = diagnostic_directory / f"policy-{number:04d}-{uuid4().hex[:8]}.bin"
                            _write_private(saved, raw)
                            reason += f" [capture locale: {saved.name}]"
                        except OSError:
                            reason += " [capture locale impossible]"
                policies.append(ConfigMgrPolicy(category, url, (), reason, error_stage))
                incomplete.append(f"stratégie #{number} ({category}), {error_stage}: {reason}")
                if "durée maximale" in str(exc) or "volume cumulé" in str(exc):
                    break
        return ConfigMgrPolicyResult(management_point, len(all_assignments), policies, incomplete)
