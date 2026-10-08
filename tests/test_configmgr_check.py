import shutil
import stat
from pathlib import Path

import pytest

from pxetrace.configmgr import _run_openssl, _write_private
from pxetrace.configmgr_check import _save_encrypted_replay


def test_no_diagnostic_key_is_saved_without_replay_public_key(tmp_path: Path) -> None:
    assert _save_encrypted_replay(b"sensitive option", b"encrypted media", output=tmp_path) is None
    assert list(tmp_path.iterdir()) == []


@pytest.mark.skipif(shutil.which("openssl") is None, reason="openssl non installé")
def test_diagnostic_response_is_sealed_and_can_be_replayed(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.delenv("SUDO_UID", raising=False)
    monkeypatch.delenv("SUDO_GID", raising=False)
    private_key = tmp_path / "test-private.pem"
    _write_private(private_key, _run_openssl(["genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:3072"]))
    _write_private(
        tmp_path / "configmgr-debug-public.pem",
        _run_openssl(["pkey", "-in", str(private_key), "-pubout"]),
    )
    option = b"SYNTHETIC PRIVATE OPTION" * 10
    blob = b"encrypted media data"
    replay = _save_encrypted_replay(option, blob, output=tmp_path)
    assert replay is not None
    sealed = (replay / "option243.sealed").read_bytes()
    assert sealed != option
    assert option not in sealed
    recovered = _run_openssl(
        [
            "pkeyutl", "-decrypt", "-inkey", str(private_key),
            "-pkeyopt", "rsa_padding_mode:oaep", "-pkeyopt", "rsa_oaep_md:sha256",
            "-pkeyopt", "rsa_mgf1_md:sha256",
        ],
        data=sealed,
    )
    assert recovered == option
    assert (replay / "variables.encrypted").read_bytes() == blob
    assert stat.S_IMODE(replay.stat().st_mode) == 0o700
    assert all(stat.S_IMODE(item.stat().st_mode) == 0o600 for item in replay.iterdir())
