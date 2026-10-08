from __future__ import annotations

from pathlib import Path

from pxetrace.cli import _apply_autopilot_defaults, build_parser


def test_normal_help_is_short_but_advanced_help_is_complete() -> None:
    short = build_parser().format_help()
    advanced = build_parser(show_advanced=True).format_help()
    assert "--output" in short
    assert "--max-files" not in short
    assert "--max-files" in advanced
    assert "--interface" in advanced


def test_positional_interface_gets_autonomous_defaults() -> None:
    args = build_parser().parse_args(["enp1s0"])
    _apply_autopilot_defaults(args)
    assert args.interface == "enp1s0"
    assert args.profile
    assert isinstance(args.output, Path)
    assert args.output.parent == Path("pxetrace-output")
    assert args.report is None


def test_extended_wim_audit_is_opt_in() -> None:
    normal = build_parser().parse_args(["enp1s0"])
    enabled = build_parser().parse_args(["enp1s0", "--full-audit"])
    assert normal.full_audit is False
    assert enabled.full_audit is True
