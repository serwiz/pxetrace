"""Targeted live check of option 243 and media variables, without WIM transfers."""

from __future__ import annotations

import os
import subprocess
import tempfile
from pathlib import Path

from .cli import _apply_autopilot_defaults, _make_identity, build_parser
from .configmgr import (
    ConfigMgrError,
    _media_ciphertext,
    _run_openssl,
    _write_private,
    decrypt_media_variables,
    validate_variables_path,
)
from .dhcp import (
    DhcpError,
    decode_configmgr_boot_variables,
    interface_ipv4,
    query_wds_nbp,
)
from .trace import Tracer
from .transfer import Fetcher, TransferError, boot_uri


def _save_encrypted_replay(option: bytes, blob: bytes, *, output: Path | None = None) -> Path | None:
    """Seal a diagnostic response for local replay; never persist the raw key."""
    if output is None:
        output = Path(__file__).resolve().parent.parent / "pxetrace-output"
    public_key = output / "configmgr-debug-public.pem"
    if not public_key.is_file():
        return None
    sealed_option = _run_openssl(
        [
            "pkeyutl", "-encrypt", "-pubin", "-inkey", str(public_key),
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        data=option,
    )
    replay = Path(tempfile.mkdtemp(prefix="configmgr-debug-", dir=output))
    _write_private(replay / "option243.sealed", sealed_option)
    _write_private(replay / "variables.encrypted", blob)
    uid_text, gid_text = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid_text and gid_text and os.geteuid() == 0:
        uid, gid = int(uid_text), int(gid_text)
        if uid >= 0 and gid >= 0:
            for item in replay.iterdir():
                os.chown(item, uid, gid)
            os.chown(replay, uid, gid)
    return replay


def main() -> int:
    # Reuse autonomous interface and firmware identity detection. No raw key,
    # decrypted value or certificate is printed or persisted by this check.
    tracer = Tracer(compact=True)
    args = build_parser().parse_args()
    try:
        _apply_autopilot_defaults(args)
        server = args.boot_server or args.server
        if not server:
            raise ValueError("indiquez le serveur PXE avec --server")
        identity = _make_identity(args)
        replies, _final = query_wds_nbp(
            args.interface,
            identity,
            tracer,
            server=server,
            station_ip=args.station_ip or interface_ipv4(args.interface),
            timeout=args.timeout,
            max_wait=30.0,
        )
        reply = next((item for item in reversed(replies) if item.options.get(243)), None)
        if reply is None:
            raise ConfigMgrError("aucune option 243 reçue; déchiffrement non testé")
        option = reply.options[243]
        info = decode_configmgr_boot_variables(option)
        if info.get("malformed") or info.get("unsupported"):
            raise ConfigMgrError("option 243 invalide ou incompatible")
        if info.get("password_protected"):
            raise ConfigMgrError("média protégé par mot de passe; clé automatique indisponible")
        path = info.get("path")
        if not isinstance(path, str):
            raise ConfigMgrError("chemin des variables absent de l'option 243")
        path = validate_variables_path(path)
        server = reply.effective_boot_server or reply.source_ip or server
        with tempfile.TemporaryDirectory(prefix="pxetrace-configmgr-check-") as temporary:
            fetcher = Fetcher(Path(temporary), tracer, max_bytes=16 * 1024 * 1024)
            fetched = fetcher.fetch(boot_uri(server, path))
            blob = fetched.path.read_bytes()
            ciphertext, plaintext_size, algorithm = _media_ciphertext(blob)
            print(
                f"Enveloppe valide : {len(ciphertext)} octets chiffrés, "
                f"{plaintext_size} octets en clair annoncés (ALG_ID 0x{algorithm:04x})."
            )
            print("Clé testée : option 243 reçue avec ce chemin de variables.")
            try:
                media = decrypt_media_variables(blob, option)
            except ConfigMgrError:
                try:
                    replay = _save_encrypted_replay(option, blob)
                    if replay:
                        print(f"Capture de diagnostic chiffrée : {replay}")
                except (ConfigMgrError, OSError, ValueError):
                    print("Capture chiffrée indisponible; aucune clé enregistrée.")
                raise
            print("Déchiffrement et XML : valides.")
            print(f"Management Points : {len(media.management_points)}.")
            print(f"Certificat média présent : {media.pfx is not None}.")
            print("Aucune clé ni variable déchiffrée conservée.")
        return 0
    except (ValueError, DhcpError, ConfigMgrError, TransferError, OSError, subprocess.SubprocessError) as exc:
        print(f"Diagnostic ConfigMgr : {exc}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
