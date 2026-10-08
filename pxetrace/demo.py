"""Ephemeral offline integration bench with invented credentials only."""
from __future__ import annotations

import io
import shutil
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path
from typing import Any

from .configmgr import (
    _TSPXE_KEY,
    _cryptderivekey_material,
    _decrypt_cms,
    _run_openssl,
    _write_private,
    decrypt_media_variables,
    expand_policy_payload,
)
from .configmgr_report import media_inventory
from .evidence import extract_credentials
from .image_audit import audit_images
from .models import BootTarget


def _encrypted_media() -> tuple[bytes, bytes]:
    # Generated per run; no captured client keys or addresses in this fixture.
    password = bytes(range(1, 11))

    def encrypt(data: bytes, key: bytes) -> bytes:
        return _run_openssl(["enc", "-aes-256-cbc", "-K", key[:32].hex(), "-iv", "00" * 16], data=data)

    wrapped = struct.pack("<5I", 20, 10, 16, 0x6610, 0) + encrypt(password, _cryptderivekey_material(_TSPXE_KEY))
    structure = bytes([len(wrapped)]) + wrapped
    option = bytes([2, len(structure)]) + structure
    xml = ('<MediaVarList><var name="SMSTSMP">http://pxe.example.test</var>'
           '<var name="OSDJoinAccount">DEMO\\join</var>'
           '<var name="OSDJoinPassword">Demo-Join-Only!</var></MediaVarList>').encode("utf-16le")
    expanded = b"".join(bytes((byte, 0)) for byte in password)
    encrypted = encrypt(xml, _cryptderivekey_material(expanded))
    return struct.pack("<6I", 0xECED0000, 20, len(xml), len(encrypted), 0x6610, 0) + encrypted, option


def demo_summary() -> dict[str, Any]:
    blob, option = _encrypted_media()
    media = decrypt_media_variables(blob, option)
    evidence = [item.as_dict() for item in extract_credentials(media.plaintext, source="SMSTemp/demo.boot.var")]
    with tempfile.TemporaryDirectory(prefix="pxetrace-demo-") as temporary:
        directory = Path(temporary)
        key, cert = directory / "media.key", directory / "media.crt"
        _run_openssl(["req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=PXETRACE-DEMO",
                      "-keyout", str(key), "-out", str(cert), "-days", "1"])
        naa = (b'<Policy><instance class="CCM_NetworkAccessAccount">'
               b'<property name="NetworkAccessUsername"><value>DEMO\\naa</value></property>'
               b'<property name="NetworkAccessPassword"><value>Demo-NAA-Only!</value></property>'
               b'</instance></Policy>')
        compressed = ('<PolicyXML Compression="zlib">' + zlib.compress(naa).hex() + '</PolicyXML>').encode()
        cms = _run_openssl(["cms", "-encrypt", "-binary", "-aes-256-cbc", "-outform", "DER",
                            "-recip", str(cert), "-keyopt", "rsa_padding_mode:oaep"], data=compressed)
        for payload in expand_policy_payload(_decrypt_cms(cms, cert, key)):
            evidence.extend(item.as_dict() for item in extract_credentials(payload, source="ConfigMgr #1 NAAConfig"))
        files = directory / "files" / "Deploy"
        files.mkdir(parents=True)
        _write_private(files / "Bootstrap.ini", b"[Default]\nUserDomain=DEMO\nUserID=deploy\nUserPassword=Demo-Deploy-Only!\n")
        wimlib = shutil.which("wimlib-imagex")
        if wimlib:
            image = directory / "boot.wim"
            subprocess.run([wimlib, "capture", str(directory / "files"), str(image), "--compress=none"],
                           check=True, capture_output=True, timeout=60)
        else:
            image = directory / "boot.zip"
            buffer = io.BytesIO()
            with zipfile.ZipFile(buffer, "w") as archive:
                archive.writestr("Deploy/Bootstrap.ini", (files / "Bootstrap.ini").read_bytes())
            _write_private(image, buffer.getvalue())
        images = audit_images([BootTarget("tftp://pxe.example.test/" + image.name, local_path=image)])
    return {
        "offline": True, "demo": True, "boot": {"effective_boot_server": "pxe.example.test (192.0.2.20)"},
        "output_path": "aucun fichier conservé par la démonstration",
        "configmgr": {"variables_decrypted": True, "variable_inventory": media_inventory(media),
                      "credentials": evidence, "policies_downloaded": 1, "policy_assignments": 1,
                      "findings": [{"severity": "critical", "category": "média PXE sans mot de passe", "path": "option 243 fictive"}], "incomplete": []},
        "image_audit": images.as_dict(),
    }
