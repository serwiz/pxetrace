from __future__ import annotations

import shutil
import struct
import subprocess
import urllib.request
import zlib

import pytest

from pxetrace.configmgr import (
    ConfigMgrDecryptionError,
    ConfigMgrError,
    _cryptderivekey_material,
    _decrypt_cms,
    _media_ciphertext,
    _policy_assignments,
    _urlopen,
    decrypt_media_variables,
    expand_policy_payload,
    recover_blank_media_password,
    validate_variables_path,
)

# Fixed synthetic vectors generated independently with PyCryptodome AES-256.
# These are deliberately not regenerated with the production crypto functions:
# the old test encrypted with AES-128 while advertising CALG_AES_256 (0x6610).
_AES256_OPTION = bytes.fromhex(
    "023130140000000a000000100000001066000000000000"
    "e99d6561c3a3b8b44f820f972fac34c7000000000000000000000000"
)
_AES256_MEDIA = bytes.fromhex(
    "0000edec1400000082000000900000001066000000000000"
    "f025d29d63c9fcccad79e9facbea6c0e7e9b1ed8c98f2447b2768f4b061d5a90"
    "974886e67b845cea902bdf19a5f96e51837ee37040137d6965096ef78aaa9f8b6"
    "2e7c54904e32192098a2380c88db1a6fbafe7b11d0bc48a84985dcb7fb847e55"
    "44e0b64bc8a2203c8b44ce881ee3aa3cc54e2693b9dd02953215e00fd5f4897c"
    "d08e5fac713b680f304ef16b38b1265000000000000"
)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_independent_aes256_media_vector() -> None:
    media = decrypt_media_variables(_AES256_MEDIA, _AES256_OPTION)
    assert media.site_code == "ABC"
    assert media.plaintext.decode("utf-16le") == (
        '<MediaVarList><var name="_SMSTSSiteCode">ABC</var></MediaVarList>'
    )


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_media_uses_its_own_advertised_algorithm() -> None:
    blob = bytearray(_AES256_MEDIA)
    struct.pack_into("<I", blob, 16, 0x660E)  # Advertise AES-128 for AES-256 ciphertext.
    with pytest.raises(ConfigMgrDecryptionError) as failure:
        decrypt_media_variables(bytes(blob), _AES256_OPTION)
    assert failure.value.stage == "variables-decryption"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_media_padding_is_checked_before_xml() -> None:
    blob = bytearray(_AES256_MEDIA)
    # Flip the final byte of the penultimate CBC block to corrupt the last
    # padding byte deterministically, without altering the key envelope.
    ciphertext_size = struct.unpack_from("<I", blob, 12)[0]
    blob[24 + ciphertext_size - 17] ^= 1
    with pytest.raises(ConfigMgrDecryptionError) as failure:
        decrypt_media_variables(bytes(blob), _AES256_OPTION)
    assert failure.value.stage == "variables-decryption"


def _encrypt(plaintext: bytes, key: bytes, bits: int = 256) -> bytes:
    completed = subprocess.run(
        [
            "openssl",
            "enc",
            f"-aes-{bits}-cbc",
            "-e",
            "-K",
            key[:bits // 8].hex(),
            "-iv",
            "00" * 16,
            "-nopad",
        ],
        input=plaintext,
        capture_output=True,
        check=True,
    )
    return completed.stdout


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_configmgr_cms_policy_is_decrypted(tmp_path) -> None:
    key = tmp_path / "recipient.key"
    cert = tmp_path / "recipient.crt"
    plain = tmp_path / "policy.xml"
    encrypted = tmp_path / "policy.cms"
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-subj", "/CN=pxetrace-test",
         "-keyout", str(key), "-out", str(cert), "-days", "1"],
        check=True, capture_output=True,
    )
    content = b"<NAAConfig><NetworkAccessUsername>audit-user</NetworkAccessUsername></NAAConfig>"
    plain.write_bytes(content)
    command = ["openssl", "cms", "-encrypt", "-binary", "-in", str(plain), "-out", str(encrypted), "-outform", "DER"]
    command.append(str(cert))
    subprocess.run(command, check=True, capture_output=True)
    assert _decrypt_cms(encrypted.read_bytes(), cert, key) == content

    oaep_encrypted = tmp_path / "policy-oaep.cms"
    oaep_command = [
        "openssl", "cms", "-encrypt", "-binary", "-aes-256-cbc", "-in", str(plain),
        "-out", str(oaep_encrypted), "-outform", "DER", "-recip", str(cert),
        "-keyopt", "rsa_padding_mode:oaep", "-keyopt", "rsa_oaep_md:sha256",
        "-keyopt", "rsa_mgf1_md:sha256",
    ]
    subprocess.run(oaep_command, check=True, capture_output=True)
    assert _decrypt_cms(oaep_encrypted.read_bytes(), cert, key) == content
    # A renewed certificate can identify the same RSA key with a new serial.
    renewed = tmp_path / 'renewed.crt'
    subprocess.run(['openssl', 'req', '-x509', '-key', str(key), '-subj', '/CN=renewed',
                    '-set_serial', '99', '-out', str(renewed), '-days', '1'], check=True, capture_output=True)
    assert _decrypt_cms(oaep_encrypted.read_bytes(), renewed, key) == content
    with pytest.raises(ConfigMgrDecryptionError) as error:
        _decrypt_cms(b'X' * 4096, cert, key)
    assert error.value.stage == 'cms-envelope'
    wrong_key = tmp_path / 'wrong.key'
    subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:2048',
                    '-out', str(wrong_key)], check=True, capture_output=True)
    with pytest.raises(ConfigMgrDecryptionError):
        _decrypt_cms(oaep_encrypted.read_bytes(), cert, wrong_key)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
@pytest.mark.parametrize("trailer_size", [0, 6, 8])
@pytest.mark.parametrize(("key_algorithm", "key_bits"), [(0x660E, 128), (0x660F, 192), (0x6610, 256)])
@pytest.mark.parametrize(("media_algorithm", "media_bits"), [(0x660E, 128), (0x660F, 192), (0x6610, 256)])
def test_blank_pxe_media_variables_are_decrypted_without_persisting_secrets(
    trailer_size: int, key_algorithm: int, key_bits: int, media_algorithm: int, media_bits: int,
) -> None:
    raw_password = bytes((1, 0x82, 3, 4, 5, 6, 7, 8, 9, 10))
    expanded = b"".join(bytes((byte, 0xFF if byte & 0x80 else 0)) for byte in raw_password)
    tspxe_key = bytes.fromhex("9f679c9b373a1f48824f378733de24e9")
    wrapped_ciphertext = _encrypt(raw_password + b"\x06" * 6, _cryptderivekey_material(tspxe_key), key_bits)
    wrapped = struct.pack("<5I", 20, 10, 16, key_algorithm, 0) + wrapped_ciphertext + bytes(12)
    structure = bytes((len(wrapped),)) + wrapped
    path = b"SMSTemp\\test.var"
    option = bytes((2, len(structure))) + structure + b"\0" + bytes((len(path),)) + path

    xml = (
        '<MediaVarList><var name="_SMSTSSiteCode">ABC</var>'
        '<var name="_SMSMediaGuid">GUID-VALUE</var>'
        '<var name="_smstsmp">HTTP://mp.example.test/</var>'
        '<var name="_SMSTSMediaPFX">01020304</var></MediaVarList>'
    ).encode("utf-16le")
    padding_size = 16 - len(xml) % 16
    padded = xml + bytes((padding_size,)) * padding_size
    encrypted = _encrypt(padded, _cryptderivekey_material(expanded), media_bits)
    header = struct.pack("<6I", 0xECED0000, 20, len(xml), len(encrypted), media_algorithm, 0)
    blob = header + encrypted + b"T" * trailer_size

    media = decrypt_media_variables(blob, option)

    assert media.site_code == "ABC"
    assert media.management_points == ("http://mp.example.test",)
    assert media.pfx == b"\x01\x02\x03\x04"
    assert "PFX" not in repr(media.public_dict())


def test_all_policy_assignment_urls_are_deduplicated() -> None:
    xml = """<ReplyAssignments>
      <PolicyAssignment><Policy PolicyCategory="TaskSequence"><PolicyLocation>http://&lt;mp&gt;/a</PolicyLocation></Policy></PolicyAssignment>
      <PolicyAssignment><Policy PolicyID="{B}"><PolicyLocation>http://&lt;mp&gt;/b</PolicyLocation></Policy></PolicyAssignment>
      <PolicyAssignment><Policy><PolicyLocation>http://&lt;mp&gt;/a</PolicyLocation></Policy></PolicyAssignment>
    </ReplyAssignments>"""
    assert _policy_assignments(xml, "http://mp.example") == [
        ("TaskSequence", "http://mp.example/a"),
        ("{B}", "http://mp.example/b"),
    ]


def test_nested_zlib_policy_payload_is_expanded_recursively() -> None:
    deepest = b'<sequence><variable name="OSDJoinPassword">masked-value</variable></sequence>'
    middle = f"<Collection>{zlib.compress(deepest).hex()}</Collection>".encode()
    outer = f"<Policy>{zlib.compress(middle).hex()}</Policy>".encode()
    expanded = expand_policy_payload(outer)
    assert deepest in expanded
    assert len(expanded) == 3  # Never feed a compression stream to 3DES.


def test_unmarked_hex_never_becomes_random_decrypted_output(monkeypatch):
    def unexpected(*args, **kwargs):
        raise AssertionError('3DES must only see explicit secret fields')
    monkeypatch.setattr('pxetrace.configmgr._des3_deobfuscate', unexpected)
    raw = b'<Policy><value>' + b'ABCDEF' * 100 + b'</value></Policy>'
    assert expand_policy_payload(raw) == (raw,)


def test_secret_fields_keep_name_and_account_context_after_decryption(monkeypatch):
    from pxetrace.evidence import extract_credentials
    monkeypatch.setattr('pxetrace.configmgr._des3_deobfuscate', lambda value: {'user-blob': b'DEMO\\naa', 'pass-blob': b'Secret!'}[value])
    raw = (b'<Policy><instance class="CCM_NetworkAccessAccount">'
           b'<property name="NetworkAccessUsername" secret="1"><value>user-blob</value></property>'
           b'<property name="NetworkAccessPassword" secret="1"><value>pass-blob</value></property>'
           b'</instance></Policy>')
    payloads = expand_policy_payload(raw)
    assert len(payloads) == 2
    evidence = [item for payload in payloads for item in extract_credentials(payload, source='NAAConfig')]
    assert len(evidence) == 1
    assert evidence[0].account == 'DEMO\\naa' and evidence[0].secret == 'Secret!'


def test_cms_failure_keeps_private_replay_material(monkeypatch, tmp_path):
    from pxetrace.configmgr import MediaVariables, audit_management_point
    metadata = b'<Root><UnknownMachines x64UnknownMachineGUID="demo-client"/><SITECODE>ABC</SITECODE></Root>'
    assignments = zlib.compress(b'<Reply><Policy PolicyCategory="NAAConfig"><PolicyLocation>http://mp.example/policy</PolicyLocation></Policy></Reply>')
    raw = b'not-a-valid-cms-response'
    replies = iter([(metadata, ''), (b'multipart-placeholder', ''), (raw, '')])
    monkeypatch.setattr('pxetrace.configmgr._urlopen', lambda *args, **kwargs: next(replies))
    monkeypatch.setattr('pxetrace.configmgr._multipart_parts', lambda *args: [b'header', assignments])
    monkeypatch.setattr('pxetrace.configmgr._extract_pfx', lambda *args: (tmp_path / 'cert', tmp_path / 'key'))
    monkeypatch.setattr('pxetrace.configmgr._sign', lambda *args: '00')
    def fail(*args):
        raise ConfigMgrDecryptionError('enveloppe CMS invalide', stage='cms-envelope')
    monkeypatch.setattr('pxetrace.configmgr._decrypt_cms', fail)
    directory = tmp_path / 'diagnostics'
    media = MediaVariables(b'', ('http://mp.example',), 'ABC', 'fake-media-guid', b'fake-pfx')
    result = audit_management_point(media, diagnostic_directory=directory)
    captures = list(directory.glob('*.bin'))
    assert len(captures) == 1 and captures[0].read_bytes() == raw
    assert captures[0].stat().st_mode & 0o777 == 0o600
    assert result.policies[0].error_stage == 'cms-envelope'
    assert captures[0].name in result.policies[0].error


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        (r"SMSTemp\client.boot.var", "SMSTemp/client.boot.var"),
        ("/SMS/data/variables.dat", "SMS/data/variables.dat"),
    ],
)
def test_configmgr_variables_path_is_normalized_and_bounded(source: str, expected: str) -> None:
    assert validate_variables_path(source) == expected


@pytest.mark.parametrize(
    "path",
    [
        "../Windows/System32/config/SAM.var",
        "%2e%2e/Windows/System32/config/SAM.var",
        "SMSTemp/../../secret.var",
        "http://other.example/file.var",
        "C:/Windows/file.var",
        "SMSTemp/file:stream.var",
        "SMSTemp/file.exe",
        "SMSTemp/file.var?other=1",
    ],
)
def test_configmgr_variables_path_rejects_out_of_scope_values(path: str) -> None:
    with pytest.raises(ValueError):
        validate_variables_path(path)


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_configmgr_variables_reject_truncated_ciphertext() -> None:
    raw_password = bytes(range(10))
    wrapped_ciphertext = _encrypt(raw_password + b"\x06" * 6, _cryptderivekey_material(bytes.fromhex("9f679c9b373a1f48824f378733de24e9")))
    wrapped = struct.pack("<5I", 20, 10, 16, 0x6610, 0) + wrapped_ciphertext + bytes(12)
    structure = bytes((len(wrapped),)) + wrapped
    option = bytes((2, len(structure))) + structure
    header = struct.pack("<6I", 0xECED0000, 20, 12, 16, 0x6610, 0)
    with pytest.raises(ConfigMgrError, match="tronquée"):
        decrypt_media_variables(header + b"short" + b"T" * 8, option)


def test_real_capture_envelope_lengths_preserve_complete_ciphertext() -> None:
    header = bytes.fromhex("0000edec1400000064340000703400001066000000000000")
    ciphertext = b"C" * 13424
    extracted, plaintext_size, algorithm = _media_ciphertext(header + ciphertext + b"T" * 6)
    assert extracted == ciphertext
    assert plaintext_size == 13412
    assert algorithm == 0x6610  # CALG_AES_256, not CALG_AES_128 (0x660e).


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
@pytest.mark.parametrize("padding", [bytes(6), b"\x06" * 5 + b"\x05"])
def test_session_key_failure_is_not_reported_as_invalid_xml(padding: bytes) -> None:
    seed = bytes.fromhex("9f679c9b373a1f48824f378733de24e9")
    ciphertext = _encrypt(bytes(range(1, 11)) + padding, _cryptderivekey_material(seed))
    wrapped = struct.pack("<5I", 20, 10, 16, 0x6610, 0) + ciphertext + bytes(12)
    structure = bytes((len(wrapped),)) + wrapped
    with pytest.raises(ConfigMgrDecryptionError, match="fin de bloc AES") as failure:
        recover_blank_media_password(bytes((2, len(structure))) + structure)
    assert failure.value.stage == "session-key-decryption"


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_session_password_stops_at_null_like_native_client() -> None:
    seed = bytes.fromhex("9f679c9b373a1f48824f378733de24e9")
    raw = bytes((0x82, 1, 0, 3, 4, 5, 6, 7, 8, 9))
    ciphertext = _encrypt(raw + b"\x06" * 6, _cryptderivekey_material(seed))
    wrapped = struct.pack("<5I", 20, 10, 16, 0x6610, 0) + ciphertext + bytes(12)
    structure = bytes((len(wrapped),)) + wrapped
    assert recover_blank_media_password(bytes((2, len(structure))) + structure) == b"\x82\xff\x01\x00"


def test_unknown_session_key_algorithm_is_explicitly_unsupported() -> None:
    wrapped = struct.pack("<5I", 20, 10, 16, 0x6611, 0) + bytes(28)
    structure = bytes((len(wrapped),)) + wrapped
    with pytest.raises(ConfigMgrDecryptionError, match="non prise en charge") as failure:
        recover_blank_media_password(bytes((2, len(structure))) + structure)
    assert failure.value.stage == "session-key-envelope"


def test_configmgr_http_requests_cannot_leave_management_point_origin() -> None:
    request = urllib.request.Request("http://other.example/SMS_MP/policy")
    with pytest.raises(ConfigMgrError, match="hors du Management Point"):
        _urlopen(request, None, 1.0, allowed_origin=("http", "mp.example", 80))


def test_nested_policy_decompression_honors_total_limit() -> None:
    compressed = zlib.compress(b"A" * 100_000).hex()
    outer = f"<Policy><Data>{compressed}</Data></Policy>".encode()
    with pytest.raises(ConfigMgrError, match="hors limites"):
        expand_policy_payload(outer, max_total_bytes=len(outer) + 1024)
