from __future__ import annotations

from io import StringIO

from pxetrace.trace import Tracer


def test_compact_trace_hides_packet_details() -> None:
    output = StringIO()
    tracer = Tracer(compact=True, stream=output)
    tracer.emit(
        "dhcp.discover",
        "recherche",
        attempt=1,
        wait_seconds=4.0,
        packet_hex="ab" * 400,
        options={"huge": "value"},
    )
    rendered = output.getvalue()
    assert rendered == "[DHCP] recherche PXE, tentative 1 (délai 4s)\n"
    assert "packet_hex" not in rendered


def test_compact_warning_stays_attached_to_its_subsystem() -> None:
    output = StringIO()
    tracer = Tracer(compact=True, stream=output)
    tracer.emit("dhcp.diagnostic", "réponse incomplète", level="warning")
    assert output.getvalue() == "       [!] réponse incomplète\n"


def test_compact_transfer_is_rendered_as_a_parent_and_child() -> None:
    output = StringIO()
    tracer = Tracer(compact=True, stream=output)
    tracer.emit("tftp.rrq", "lecture", server="192.0.2.1", filename="boot.wim")
    tracer.emit("tftp.done", "terminé", bytes=1024)
    assert output.getvalue() == (
        "[TFTP] lecture de boot.wim sur 192.0.2.1\n"
        "       [+] reçu 1.0 Kio\n"
    )


def test_compact_transfer_failure_is_not_hidden() -> None:
    output = StringIO()
    tracer = Tracer(compact=True, stream=output)
    tracer.emit("tftp.rrq", "lecture", server="192.0.2.1", filename="boot.wim")
    tracer.emit(
        "fetch.error",
        "échec",
        level="error",
        uri="tftp://192.0.2.1/boot.wim",
        reason="erreur serveur TFTP 1: File not found",
    )
    assert output.getvalue().endswith("       [!] erreur serveur TFTP 1: File not found\n")
