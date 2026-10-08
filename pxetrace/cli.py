from __future__ import annotations

import argparse
import ipaddress
import os
import platform
import re
import sys
import urllib.parse
import uuid
from datetime import datetime
from pathlib import Path

from . import __version__
from .audit import SecurityAuditor
from .chain import ChainTracer
from .configmgr import validate_variables_path
from .configmgr_inspect import ConfigMgrInspector
from .configmgr_report import write_configmgr_report
from .image_audit import audit_images
from .reports import save_reports
from .dhcp import (
    ARCHITECTURES,
    DhcpClient,
    DhcpError,
    DhcpIdentity,
    decode_configmgr_boot_variables,
    firmware_uuid,
    format_mac,
    interface_active_mac,
    interface_mac,
    interface_ipv4,
    pxe_server_addresses,
    query_pxe_boot_server,
    query_wds_nbp,
    reply_as_dict,
    select_boot_offer,
)
from .models import BootTarget, DhcpReply
from .trace import Tracer
from .transfer import Fetcher, boot_uri
from .transfer import resolve_reference


def build_parser(*, show_advanced: bool = False) -> argparse.ArgumentParser:
    advanced = (lambda text: text) if show_advanced else (lambda _text: argparse.SUPPRESS)
    parser = argparse.ArgumentParser(
        prog="pxetrace",
        description="Rejoue et documente une chaîne de démarrage PXE IPv4 sans redémarrer la machine.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    parser.add_argument("interface", nargs="?", help="interface PXE, par exemple enp1s0; détectée automatiquement si omise")
    parser.add_argument("-o", "--output", type=Path, help="répertoire de capture; un nom horodaté est créé par défaut")
    parser.add_argument("-q", "--quiet", action="store_true", help="n'affiche que le résumé et les erreurs")
    parser.add_argument("--advanced-help", action="store_true", help="affiche tous les réglages experts")
    offline = parser.add_mutually_exclusive_group()
    offline.add_argument("--offline", type=Path, help="réanalyse un dossier de capture sans réseau")
    offline.add_argument("--demo", action="store_true", help="démonstration locale éphémère avec données fictives")
    parser.add_argument(
        "-i",
        "--interface",
        "--interface-name",
        dest="interface_option",
        help=advanced("ancienne forme optionnelle de l'interface"),
    )
    parser.add_argument(
        "--profile",
        choices=sorted(ARCHITECTURES),
        help=advanced("profil d'architecture envoyé dans l'option DHCP 93; auto-détecté par défaut"),
    )
    parser.add_argument("--arch", type=int, metavar="0..65535", help=advanced("valeur brute de l'option 93; remplace --profile"))
    parser.add_argument("--mac", help=advanced("MAC annoncée; par défaut celle de l'interface"))
    parser.add_argument("--uuid", dest="machine_uuid", type=uuid.UUID, help=advanced("UUID annoncé dans l'option 97"))
    parser.add_argument("--hostname", help=advanced("nom envoyé dans l'option 12"))
    parser.add_argument("--vendor-class", help=advanced("option 60 exacte"))
    parser.add_argument("--undi", default="3.16", help=advanced("version UNDI majeure.mineure de l'option 94"))
    parser.add_argument("--user-class", help=advanced("option 77 brute, par exemple iPXE"))
    parser.add_argument(
        "--discover-only",
        action="store_true",
        help=advanced("n'émet pas DHCPREQUEST après les offres"),
    )
    parser.add_argument("--timeout", type=float, default=4.0, help=advanced("délai réseau de base"))
    parser.add_argument("--dhcp-attempts", type=int, default=4, help=advanced("nombre de tentatives DHCP"))
    parser.add_argument("--client-port", type=int, default=68, help=advanced("port UDP client DHCP"))
    parser.add_argument("--server-port", type=int, default=67, help=advanced("port UDP du serveur DHCP"))
    parser.add_argument("--no-raw-dhcp", action="store_true", help=advanced("désactive l'émission DHCP IPv4 brute"))
    parser.add_argument("--station-ip", help=advanced("IPv4 locale pour l'échange PXE/4011"))
    parser.add_argument("--boot-server", help=advanced("Boot Server PXE/4011 explicite"))
    parser.add_argument("--boot-server-port", type=int, default=4011, help=advanced("port du PXE Boot Server"))
    parser.add_argument("--boot-type", type=int, default=0, metavar="0..65535", help=advanced("type PXE demandé"))
    parser.add_argument("--boot-layer", type=int, default=0, metavar="0..65535", help=advanced("couche PXE demandée"))
    parser.add_argument("--no-boot-service-discovery", action="store_true", help=advanced("désactive la découverte UDP/4011"))
    parser.add_argument("--server", help=advanced("serveur TFTP de reprise"))
    parser.add_argument("--boot-file", help=advanced("fichier ou URL initial de reprise"))
    parser.add_argument("--no-fetch", action="store_true", help=advanced("s'arrête après DHCP"))
    parser.add_argument("--no-ipxe-second-stage", action="store_true", help=advanced("désactive le second DHCP iPXE"))
    parser.add_argument("--follow-heuristics", action="store_true", help=advanced("suit également tous les indices binaires incertains"))
    parser.add_argument("--max-depth", type=int, default=32, help=advanced("profondeur maximale de la chaîne"))
    parser.add_argument("--max-files", type=int, default=512, help=advanced("nombre maximal de transferts tentés"))
    parser.add_argument("--max-bytes", type=int, default=8 * 1024 * 1024 * 1024, help=advanced("taille maximale de chaque objet"))
    parser.add_argument("--max-inspect-bytes", type=int, default=64 * 1024 * 1024, help=advanced("octets inspectés par objet"))
    parser.add_argument("--reuse-cache", action="store_true", help=advanced("réutilise les objets existants"))
    parser.add_argument("--report", type=Path, help=advanced("chemin du rapport JSON"))
    parser.add_argument(
        "--full-audit",
        action="store_true",
        help=advanced("réactive l'ancien audit étendu des WIM, archives et fichiers téléchargés"),
    )
    parser.add_argument(
        "--configmgr-max-policies",
        type=int,
        default=1024,
        help=advanced("nombre maximal de stratégies ConfigMgr récupérées"),
    )
    parser.add_argument(
        "--configmgr-max-bytes",
        type=int,
        default=256 * 1024 * 1024,
        help=advanced("volume décompressé cumulé maximal des stratégies ConfigMgr"),
    )
    parser.add_argument(
        "--configmgr-max-seconds",
        type=float,
        default=300.0,
        help=advanced("durée totale maximale du contrôle du Management Point"),
    )
    parser.add_argument("-v", "--verbose", action="store_true", help=advanced("affiche la chronologie complète"))
    return parser


def _detect_interface() -> str:
    try:
        routes = Path("/proc/net/route").read_text(encoding="ascii").splitlines()[1:]
    except OSError:
        routes = []
    for line in routes:
        fields = line.split()
        if len(fields) >= 4 and fields[1] == "00000000" and int(fields[3], 16) & 0x2 and fields[0] != "lo":
            return fields[0]
    candidates = [
        path.name
        for path in Path("/sys/class/net").glob("*")
        if path.name != "lo"
        and (path / "operstate").read_text(encoding="ascii", errors="ignore").strip() == "up"
    ]
    if len(candidates) == 1:
        return candidates[0]
    raise ValueError("interface indéterminée; utilisez simplement: pxetrace <interface>")


def _automatic_profile() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "uefi-x64"
    if machine in {"i386", "i486", "i586", "i686", "x86"}:
        return "uefi-ia32"
    if machine in {"aarch64", "arm64"}:
        return "uefi-arm64"
    if machine.startswith("arm"):
        return "uefi-arm32"
    raise ValueError(f"architecture {machine!r} inconnue; utilisez --profile via --advanced-help")


def _safe_run_name(interface: str) -> str:
    safe_interface = re.sub(r"[^A-Za-z0-9_.-]", "_", interface)
    timestamp = datetime.now().astimezone().strftime("%Y%m%d-%H%M%S")
    return f"{timestamp}-{safe_interface}"


def _apply_autopilot_defaults(args: argparse.Namespace) -> None:
    positional = args.interface
    optional = args.interface_option
    if positional and optional and positional != optional:
        raise ValueError(f"deux interfaces différentes ont été indiquées: {positional!r} et {optional!r}")
    args.interface = positional or optional
    if not args.boot_file and not args.interface:
        args.interface = _detect_interface()
    if args.profile is None:
        args.profile = _automatic_profile()
    args.automatic_output = args.output is None
    if args.output is None:
        args.output = Path("pxetrace-output") / _safe_run_name(args.interface or "replay")


def _hand_back_output(path: Path, *, include_parent: bool) -> None:
    """Give sudo-created captures back to the invoking desktop user."""
    uid_text, gid_text = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid_text or not gid_text:
        return
    try:
        uid, gid = int(uid_text), int(gid_text)
    except ValueError:
        return
    if uid < 0 or gid < 0 or not path.exists():
        return
    for directory, names, files in os.walk(path, topdown=False, followlinks=False):
        for name in [*names, *files]:
            os.chown(Path(directory) / name, uid, gid, follow_symlinks=False)
        os.chown(directory, uid, gid, follow_symlinks=False)
    if include_parent and path.parent.name == "pxetrace-output":
        os.chown(path.parent, uid, gid, follow_symlinks=False)


def _parse_undi(value: str) -> tuple[int, int]:
    try:
        major_text, minor_text = value.split(".", 1)
        major, minor = int(major_text), int(minor_text)
    except (ValueError, AttributeError) as exc:
        raise ValueError("--undi doit avoir la forme majeure.mineure, par exemple 3.16") from exc
    if not 0 <= major <= 255 or not 0 <= minor <= 255:
        raise ValueError("les composantes UNDI doivent être comprises entre 0 et 255")
    return major, minor


def _make_identity(args: argparse.Namespace) -> DhcpIdentity:
    if not args.interface:
        raise ValueError("--interface est requis pour une négociation DHCP réelle")
    if args.mac:
        from .dhcp import parse_mac

        mac = parse_mac(args.mac)
    else:
        mac = interface_mac(args.interface)
    arch = args.arch if args.arch is not None else ARCHITECTURES[args.profile]
    undi_major, undi_minor = _parse_undi(args.undi)
    vendor_class = args.vendor_class or f"PXEClient:Arch:{arch:05d}:UNDI:{undi_major:03d}{undi_minor:03d}"
    try:
        vendor_class.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("--vendor-class doit être ASCII") from exc
    return DhcpIdentity(
        mac=mac,
        arch=arch,
        machine_uuid=args.machine_uuid or firmware_uuid(),
        vendor_class=vendor_class,
        undi_major=undi_major,
        undi_minor=undi_minor,
        hostname=args.hostname,
        user_class=args.user_class,
    )


def _is_ipxe_program(targets: list[BootTarget]) -> bool:
    if not targets:
        return False
    first = targets[0]
    name = urllib.parse.urlsplit(first.uri).path.rsplit("/", 1)[-1].lower()
    if any(marker in name for marker in ("ipxe", "snponly", "undionly", "snp.efi")):
        return True
    if first.local_path:
        try:
            with first.local_path.open("rb") as downloaded:
                sample = downloaded.read(4 * 1024 * 1024)
        except OSError:
            return False
        return b"iPXE" in sample or b"http://ipxe.org" in sample
    return False


def _is_pxelinux_program(targets: list[BootTarget]) -> bool:
    if not targets:
        return False
    name = urllib.parse.urlsplit(targets[0].uri).path.rsplit("/", 1)[-1].lower()
    return name in {"pxelinux.0", "lpxelinux.0"}


def _is_wds_manager(targets: list[BootTarget]) -> bool:
    return bool(targets) and urllib.parse.urlsplit(targets[0].uri).path.rsplit("/", 1)[-1].lower() == "wdsmgfw.efi"


def _pxelinux_config_uris(base_uri: str, mac: bytes, client_ip: str | None) -> list[str]:
    names = ["01-" + "-".join(f"{octet:02x}" for octet in mac)]
    if client_ip and client_ip != "0.0.0.0":
        hexadecimal = f"{int(ipaddress.IPv4Address(client_ip)):08X}"
        names.extend(hexadecimal[:length] for length in range(8, 0, -1))
    names.append("default")
    return [resolve_reference(base_uri, "pxelinux.cfg/" + name) for name in names]


def _dhcp_round(
    args: argparse.Namespace,
    identity: DhcpIdentity,
    tracer: Tracer,
) -> tuple[list[DhcpReply], DhcpReply | None, DhcpReply | None]:
    client = DhcpClient(
        args.interface,
        identity,
        tracer,
        timeout=args.timeout,
        attempts=args.dhcp_attempts,
        client_port=args.client_port,
        server_port=args.server_port,
        use_raw_broadcast=not args.no_raw_dhcp,
        require_pxe_offer=not bool(args.boot_server),
    )
    replies, ack = client.exchange(commit_lease=not args.discover_only)
    candidates = replies + ([ack] if ack is not None else [])
    lease, boot, _diagnostics = select_boot_offer(candidates)
    return candidates, lease, boot


def _complete_boot_discovery(
    args: argparse.Namespace,
    identity: DhcpIdentity,
    tracer: Tracer,
) -> tuple[list[DhcpReply], DhcpReply | None, DhcpReply | None]:
    replies, lease, boot = _dhcp_round(args, identity, tracer)
    if boot is None and not args.no_boot_service_discovery:
        servers = (
            [args.boot_server]
            if args.boot_server
            else pxe_server_addresses(replies, boot_type=args.boot_type)
        )
        if servers:
            try:
                station_ip = args.station_ip or interface_ipv4(args.interface)
            except DhcpError as exc:
                tracer.emit(
                    "pxe.station-ip",
                    "découverte UDP/4011 impossible sans IPv4 locale",
                    level="error",
                    reason=str(exc),
                )
            else:
                if lease and lease.yiaddr != station_ip:
                    tracer.emit(
                        "pxe.station-ip",
                        "l'adresse offerte diffère de l'adresse déjà configurée; l'échange 4011 utilise l'adresse locale",
                        level="warning",
                        offered=lease.yiaddr,
                        local=station_ip,
                    )
                for pxe_server in servers:
                    try:
                        discovered = query_pxe_boot_server(
                            args.interface,
                            identity,
                            tracer,
                            server=pxe_server,
                            station_ip=station_ip,
                            timeout=args.timeout,
                            client_port=args.client_port,
                            boot_server_port=args.boot_server_port,
                            boot_type=args.boot_type,
                            layer=args.boot_layer,
                        )
                    except DhcpError as exc:
                        tracer.emit(
                            "pxe.discover",
                            "échec de la découverte PXE Boot Server",
                            level="error",
                            server=pxe_server,
                            reason=str(exc),
                        )
                        continue
                    if discovered is not None:
                        replies.append(discovered)
                        _ignored_lease, boot, _diagnostics = select_boot_offer(replies)
                        if boot:
                            break
    lease, boot, diagnostics = select_boot_offer(replies)
    for diagnostic in diagnostics:
        tracer.emit(
            "dhcp.diagnostic",
            diagnostic,
            level="info" if "ProxyDHCP" in diagnostic else "warning",
        )
    return replies, lease, boot


def _summary_text(summary: dict[str, object]) -> str:
    from .presentation import render_audit_screen

    return render_audit_screen(summary, color=sys.stdout.isatty() and not os.environ.get("NO_COLOR"))


def run(args: argparse.Namespace) -> int:
    if args.demo:
        from .demo import demo_summary
        print(_summary_text(demo_summary()))
        return 0
    if args.offline:
        from .offline import inspect_capture
        offline_summary = inspect_capture(args.offline)
        if args.output:
            save_reports(args.output.resolve(), offline_summary)
        print(_summary_text(offline_summary))
        return 0
    _apply_autopilot_defaults(args)
    if args.timeout <= 0:
        raise ValueError("--timeout doit être positif")
    if args.max_depth < 0 or args.max_files < 1 or args.max_bytes < 1 or args.max_inspect_bytes < 1:
        raise ValueError("les limites doivent être positives")
    if args.configmgr_max_policies < 1 or args.configmgr_max_bytes < 1 or args.configmgr_max_seconds <= 0:
        raise ValueError("les limites ConfigMgr doivent être positives")
    if not 1 <= args.dhcp_attempts <= 8:
        raise ValueError("--dhcp-attempts doit être compris entre 1 et 8")
    if args.arch is not None and not 0 <= args.arch <= 65535:
        raise ValueError("--arch doit être compris entre 0 et 65535")
    if not 0 <= args.boot_type <= 65535 or not 0 <= args.boot_layer <= 65535:
        raise ValueError("--boot-type et --boot-layer doivent être compris entre 0 et 65535")
    for name in ("client_port", "server_port", "boot_server_port"):
        if not 1 <= getattr(args, name) <= 65535:
            raise ValueError(f"--{name.replace('_', '-')} doit être compris entre 1 et 65535")
    if bool(args.server) != bool(args.boot_file):
        # A full URL is self-contained and does not require --server.
        if not (args.boot_file and urllib.parse.urlsplit(args.boot_file).scheme and not args.server):
            raise ValueError("utilisez --server et --boot-file ensemble, ou fournissez une URL complète à --boot-file")

    tracer = Tracer(verbose=args.verbose, compact=not args.quiet)
    report_path = args.report.resolve() if args.report else None
    summary: dict[str, object] = {
        "version": __version__,
        "output_path": str(args.output.resolve()),
        "report_path": str(report_path) if report_path else None,
    }
    replies: list[DhcpReply] = []
    boot_reply: DhcpReply | None = None
    lease: DhcpReply | None = None
    identity: DhcpIdentity | None = None

    if args.boot_file:
        initial_uri = args.boot_file if urllib.parse.urlsplit(args.boot_file).scheme else boot_uri(args.server, args.boot_file)
        summary["replay"] = {"uri": initial_uri}
        tracer.emit("replay", "point de départ fourni en ligne de commande", uri=initial_uri)
    else:
        identity = _make_identity(args)
        active_mac = interface_active_mac(args.interface)
        if not args.mac and active_mac != identity.mac:
            tracer.emit(
                "identity.mac",
                "MAC Linux randomisée détectée; utilisation de la MAC matérielle comme l'UEFI",
                active_mac=format_mac(active_mac),
                pxe_mac=format_mac(identity.mac),
            )
        summary["identity"] = {
            "interface": args.interface,
            "mac": format_mac(identity.mac),
            "active_mac": format_mac(active_mac),
            "arch": identity.arch,
            "profile": args.profile,
            "uuid": str(identity.machine_uuid),
            "vendor_class": identity.vendor_class,
            "undi": f"{identity.undi_major}.{identity.undi_minor}",
            "user_class": identity.user_class,
        }
        replies, lease, boot_reply = _complete_boot_discovery(args, identity, tracer)
        summary["dhcp_replies"] = [reply_as_dict(reply) for reply in replies]
        summary["lease"] = reply_as_dict(lease) if lease else None
        summary["boot"] = reply_as_dict(boot_reply) if boot_reply else None
        if boot_reply is None or not boot_reply.effective_boot_file:
            summary["chain"] = []
            if report_path:
                tracer.write_json(report_path, summary=summary)
            _hand_back_output(args.output.resolve(), include_parent=args.automatic_output)
            print(_summary_text(summary))
            return 2
        server = boot_reply.effective_boot_server
        if not server:
            server = boot_reply.source_ip
            tracer.emit(
                "dhcp.inference",
                "serveur de boot absent; utilisation de l'adresse source de l'offre PXE",
                level="warning",
                inferred_server=server,
            )
        initial_uri = boot_uri(server, boot_reply.effective_boot_file)

    configmgr_option_243: bytes | None = None
    initial = BootTarget(uri=initial_uri, source="command-line" if args.boot_file else "DHCP/ProxyDHCP")
    if args.no_fetch:
        initial.status = "identified-only"
        chain = [initial]
    else:
        fetcher = Fetcher(
            args.output,
            tracer,
            timeout=args.timeout,
            max_bytes=args.max_bytes,
            reuse_cache=args.reuse_cache,
        )
        chain_tracer = ChainTracer(
            fetcher,
            tracer,
            max_depth=args.max_depth,
            max_files=args.max_files,
            follow_heuristics=args.follow_heuristics,
            max_inspect_bytes=args.max_inspect_bytes,
            variables=(
                {
                    "next-server": urllib.parse.urlsplit(initial_uri).hostname or "",
                    "filename": urllib.parse.unquote(urllib.parse.urlsplit(initial_uri).path.lstrip("/")),
                    "mac": format_mac(identity.mac),
                    "uuid": str(identity.machine_uuid),
                }
                if identity
                else None
            ),
        )
        chain = chain_tracer.trace(initial)

        if identity and _is_wds_manager(chain):
            wds_server = urllib.parse.urlsplit(initial_uri).hostname or ""
            try:
                station_ip = args.station_ip or interface_ipv4(args.interface)
                if lease and lease.yiaddr not in {"0.0.0.0", station_ip}:
                    tracer.emit(
                        "wds.station-ip",
                        "le bail PXE diffère de l'adresse réellement configurée",
                        level="warning",
                        offered=lease.yiaddr,
                        local=station_ip,
                        reason="l'échange WDS utilise l'adresse locale sans modifier l'interface",
                    )
                wds_replies, wds_reply = query_wds_nbp(
                    args.interface,
                    identity,
                    tracer,
                    server=wds_server,
                    station_ip=station_ip,
                    timeout=args.timeout,
                    client_port=args.client_port,
                    boot_server_port=args.boot_server_port,
                )
            except DhcpError as exc:
                tracer.emit(
                    "wds.request",
                    "échange de configuration impossible",
                    level="error",
                    server=wds_server,
                    reason=str(exc),
                )
                wds_replies, wds_reply = [], None
            summary["wds_replies"] = [reply_as_dict(reply) for reply in wds_replies]

            if wds_reply is not None:
                stage_server = wds_reply.effective_boot_server or wds_reply.source_ip or wds_server
                bcd_path = wds_reply.option_text(252)
                if bcd_path:
                    bcd_uri = boot_uri(stage_server, bcd_path)
                    chain_tracer.windows_bcd_uri = bcd_uri
                    next_file = wds_reply.effective_boot_file
                    if next_file:
                        next_uri = boot_uri(stage_server, next_file)
                        if next_uri != initial_uri:
                            chain.extend(
                                chain_tracer.trace(
                                    BootTarget(
                                        uri=next_uri,
                                        kind="uefi-pe",
                                        source="WDS boot reply",
                                        parent=initial_uri,
                                    )
                                )
                            )
                    # Still follow the server-provided BCD if the intermediate
                    # boot manager is absent or had already been downloaded.
                    chain.extend(
                        chain_tracer.trace(
                            BootTarget(
                                uri=bcd_uri,
                                kind="windows-bcd",
                                source="WDS option 252",
                                parent=initial_uri,
                            )
                        )
                    )

            # Some TSPXE versions send option 243 in an intermediate response
            # and omit it from the final response carrying option 252.
            variables_reply = next((reply for reply in reversed(wds_replies) if reply.options.get(243)), None)
            if variables_reply is not None:
                option_243 = variables_reply.options[243]
                configmgr_option_243 = option_243
                variables_info = decode_configmgr_boot_variables(option_243)
                summary["configmgr_option_243"] = variables_info
                variables_path = variables_info.get("path")
                try:
                    safe_variables_path = (
                        validate_variables_path(variables_path) if isinstance(variables_path, str) else None
                    )
                except ValueError as exc:
                    tracer.emit(
                        "configmgr.warning",
                        "chemin de variables ConfigMgr refusé",
                        level="error",
                        reason=str(exc),
                    )
                else:
                    if safe_variables_path:
                        variables_server = (
                            variables_reply.effective_boot_server
                            or variables_reply.source_ip
                            or wds_server
                        )
                        chain.extend(
                            chain_tracer.trace(
                                BootTarget(
                                    uri=boot_uri(variables_server, safe_variables_path),
                                    kind="configmgr-variables",
                                    source="ConfigMgr option 243",
                                    parent=initial_uri,
                                )
                            )
                        )

        if identity and _is_pxelinux_program(chain):
            client_ip = lease.yiaddr if lease else None
            for config_uri in _pxelinux_config_uris(initial_uri, identity.mac, client_ip):
                tracer.emit(
                    "pxelinux.probe",
                    "recherche du fichier de configuration selon l'ordre SYSLINUX",
                    uri=config_uri,
                )
                attempted = chain_tracer.trace(
                    BootTarget(uri=config_uri, kind="pxelinux-config", source="PXELINUX search", parent=initial_uri)
                )
                chain.extend(attempted)
                if any(item.local_path for item in attempted):
                    break

        if identity and not args.no_ipxe_second_stage and not identity.user_class and _is_ipxe_program(chain):
            tracer.emit(
                "ipxe.stage2",
                "binaire iPXE détecté; nouvelle négociation avec option 77=iPXE",
            )
            second_identity = DhcpIdentity(
                mac=identity.mac,
                arch=identity.arch,
                machine_uuid=identity.machine_uuid,
                # This is iPXE's de-facto DHCPv4 identity, as distinct from
                # the longer firmware PXEClient:Arch:... value.
                vendor_class="PXEClient",
                undi_major=identity.undi_major,
                undi_minor=identity.undi_minor,
                hostname=identity.hostname,
                user_class="iPXE",
            )
            second_replies, _second_lease, second_boot = _complete_boot_discovery(
                args,
                second_identity,
                tracer,
            )
            summary["ipxe_dhcp_replies"] = [reply_as_dict(reply) for reply in second_replies]
            if second_boot and second_boot.effective_boot_file:
                stage_server = second_boot.effective_boot_server or second_boot.source_ip
                stage_uri = boot_uri(stage_server, second_boot.effective_boot_file)
                if stage_uri != initial_uri:
                    stage_target = BootTarget(uri=stage_uri, source="DHCP user-class iPXE", parent=initial_uri)
                    chain_tracer.variables.update(
                        {
                            "next-server": urllib.parse.urlsplit(stage_uri).hostname or stage_server,
                            "filename": urllib.parse.unquote(urllib.parse.urlsplit(stage_uri).path.lstrip("/")),
                        }
                    )
                    tracer.emit(
                        "chain.edge",
                        "ressource de second étage fournie à iPXE",
                        parent=initial_uri,
                        child=stage_uri,
                        certainty="certain",
                    )
                    chain.extend(chain_tracer.trace(stage_target))
                else:
                    tracer.emit(
                        "ipxe.loop",
                        "le serveur renvoie le même binaire à iPXE; boucle de chainloading probable",
                        level="error",
                        uri=stage_uri,
                    )
            else:
                tracer.emit(
                    "ipxe.stage2",
                    "aucun fichier spécifique retourné au client iPXE",
                    level="warning",
                )

    if not args.no_fetch:
        configmgr = ConfigMgrInspector(
            tracer,
            option_243=configmgr_option_243,
            max_policies=args.configmgr_max_policies,
            max_policy_bytes=args.configmgr_max_bytes,
            max_duration=args.configmgr_max_seconds,
            diagnostic_directory=args.output.resolve() / "configmgr-diagnostics",
        ).inspect(chain)
        if configmgr.detected:
            summary["configmgr"] = configmgr.as_dict()
            try:
                configmgr_report = write_configmgr_report(args.output.resolve(), configmgr.as_dict())
                summary["configmgr_report_path"] = str(configmgr_report)
            except OSError as exc:
                tracer.emit(
                    "configmgr.warning", "rapport ConfigMgr non enregistré", level="warning", reason=str(exc),
                )
        if args.full_audit:
            # ConfigMgr has its own bounded pipeline above. Do not process it a
            # second time through the legacy broad filesystem auditor.
            summary["audit"] = SecurityAuditor(tracer).audit(chain, include_configmgr=False).as_dict()
        summary["image_audit"] = audit_images(chain).as_dict()
    summary["chain"] = [target.as_dict() for target in chain]
    save_reports(args.output.resolve(), summary)
    if report_path:
        tracer.write_json(report_path, summary=summary)
    _hand_back_output(args.output.resolve(), include_parent=args.automatic_output)
    print(_summary_text(summary))
    return 0 if any(target.local_path for target in chain) or args.no_fetch else 3


def main(argv: list[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    if "--advanced-help" in arguments:
        build_parser(show_advanced=True).print_help()
        return 0
    parser = build_parser()
    args = parser.parse_args(arguments)
    try:
        return run(args)
    except (ValueError, DhcpError, OSError) as exc:
        parser.exit(1, f"pxetrace: erreur: {exc}\n")
    return 1
