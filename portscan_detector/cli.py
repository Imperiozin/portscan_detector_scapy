from __future__ import annotations

import argparse
import ipaddress
from pathlib import Path

from scapy.all import sniff
from scapy.utils import PcapReader

from .demo_scenario import run_demo_scenario
from .detector import Direction, PortScanDetector
from .interface_listing import format_interface_names, get_interfaces, print_interfaces
from .reputation import CriticalityAssessor, load_assessor
from .storage import SQLiteEventStore
from .ui import render_operational_ui
from .web_dashboard import DEFAULT_WEB_HOST, DEFAULT_WEB_PORT, run_web_dashboard


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Detecta reconhecimento de rede com Scapy, enriquece os eventos com "
            "hipótese técnica, exposição observada, severidade e evidências."
        )
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="Arquivo .pcap/.pcapng para analisar.")
    source.add_argument("--interface", help="Interface de rede para captura ao vivo.")
    source.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Lista interfaces conhecidas pelo Scapy e encerra.",
    )
    source.add_argument(
        "--ui",
        action="store_true",
        help="Abre a interface operacional de terminal com os eventos salvos no SQLite.",
    )
    source.add_argument(
        "--web-ui",
        action="store_true",
        help="Abre o dashboard web local com os eventos salvos no SQLite.",
    )
    source.add_argument(
        "--demo-scenario",
        action="store_true",
        help=(
            "Gera um cenário sintético de reconhecimento, salva no SQLite "
            "e abre a interface operacional."
        ),
    )
    parser.add_argument(
        "--database",
        type=Path,
        default=Path("port_scans.db"),
        help="Arquivo SQLite de saida. Padrao: port_scans.db",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=8,
        help="Quantidade de portas distintas para considerar scan. Padrao: 8",
    )
    parser.add_argument(
        "--window",
        type=float,
        default=120.0,
        help="Janela de validacao em segundos. Padrao: 120",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=30.0,
        help="Tempo minimo entre alertas repetidos do mesmo par origem/destino. Padrao: 30",
    )
    parser.add_argument(
        "--alert-threshold",
        type=int,
        default=60,
        help="Criticidade minima para imprimir alerta em vermelho. Padrao: 60",
    )
    parser.add_argument(
        "--direction",
        choices=("inbound", "outbound", "both"),
        default=None,
        help="Direcao dos pacotes analisados. Padrao: inbound na captura ao vivo, both em PCAP.",
    )
    parser.add_argument(
        "--whitelist",
        type=Path,
        default=Path("whitelist.json"),
        help="Arquivo JSON de whitelist. Padrao: whitelist.json",
    )
    parser.add_argument(
        "--blacklist",
        type=Path,
        default=Path("blacklist.json"),
        help="Arquivo JSON de blacklist. Padrao: blacklist.json",
    )
    parser.add_argument(
        "--abuseipdb-key",
        default=None,
        help="Chave da AbuseIPDB. Se omitida, usa ABUSEIPDB_KEY ou a chave padrao configurada.",
    )
    parser.add_argument(
        "--greynoise-key",
        default=None,
        help="Chave da GreyNoise. Se omitida, usa GREYNOISE_KEY; sem chave tenta endpoint community.",
    )
    parser.add_argument(
        "--bpf",
        default="tcp or udp or icmp",
        help="Filtro BPF usado na captura ao vivo. Padrao: tcp or udp or icmp",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=20,
        help="Quantidade de eventos recentes exibidos na interface operacional. Padrao: 20",
    )
    parser.add_argument(
        "--host",
        default=DEFAULT_WEB_HOST,
        help=f"Endereco local da interface web. Padrao: {DEFAULT_WEB_HOST}",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=DEFAULT_WEB_PORT,
        help=f"Porta inicial da interface web. Padrao: {DEFAULT_WEB_PORT}",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.list_interfaces:
        print_interfaces()
        return

    store = SQLiteEventStore(args.database)

    if args.ui:
        render_operational_ui(store, limit=args.limit)
        return

    if args.web_ui:
        run_web_dashboard(args.database, host=args.host, port=args.port)
        return

    if args.demo_scenario:
        demo_assessor = CriticalityAssessor(
            abuseipdb_key="",
            enable_whois=False,
            enable_crowdsec=False,
            enable_greynoise=False,
        )
        detector = PortScanDetector(
            threshold=4,
            window_seconds=20.0,
            cooldown_seconds=args.cooldown,
            on_event=store.save,
            assess_event=demo_assessor.assess,
            alert_threshold=args.alert_threshold,
        )
        packet_count = run_demo_scenario(detector)
        print(
            f"Cenário demonstrativo processado: {packet_count} pacote(s) sintético(s). "
            f"Banco: {args.database}"
        )
        render_operational_ui(store, limit=args.limit)
        return

    direction = resolve_direction(args.direction, using_live_capture=bool(args.interface))
    local_networks = resolve_local_networks(args.interface)
    assessor = load_assessor(
        whitelist_path=args.whitelist,
        blacklist_path=args.blacklist,
        abuseipdb_key=args.abuseipdb_key,
        greynoise_key=args.greynoise_key,
    )

    detector = PortScanDetector(
        threshold=args.threshold,
        window_seconds=args.window,
        cooldown_seconds=args.cooldown,
        on_event=store.save,
        assess_event=assessor.assess,
        alert_threshold=args.alert_threshold,
        direction=direction,
        local_networks=local_networks,
    )

    if args.pcap:
        analyze_pcap(args.pcap, detector)
        return

    print(
        f"Capturando na interface {args.interface!r} "
        f"(direcao={direction}, filtro={args.bpf!r}). "
        "Pressione Ctrl+C para parar."
    )
    try:
        sniff(
            iface=args.interface,
            filter=args.bpf,
            prn=detector.process_packet,
            store=False,
        )
    except KeyboardInterrupt:
        print("\nCaptura encerrada.")
    except RuntimeError as error:
        message = str(error).lower()
        if "winpcap" in message or "layer 2" in message:
            raise SystemExit(
                "Captura ao vivo indisponível: o Scapy não encontrou WinPcap/Npcap.\n"
                "No Windows, instale o Npcap, marque a opção de compatibilidade "
                "com WinPcap durante a instalação e execute o terminal como "
                "administrador. Depois rode novamente com --list-interfaces para "
                "confirmar o nome da interface."
            ) from error
        raise
    except ValueError as error:
        message = str(error).lower()
        if "interface" in message and "not found" in message:
            raise SystemExit(
                f"Interface não encontrada: {args.interface!r}\n\n"
                f"{format_interface_names()}\n\n"
                "Rode `python -m portscan_detector --list-interfaces` "
                "para ver mais detalhes."
            ) from error
        raise


def analyze_pcap(path: Path, detector: PortScanDetector) -> None:
    if not path.exists():
        raise SystemExit(f"Arquivo não encontrado: {path}")

    count = 0
    with PcapReader(str(path)) as packets:
        for packet in packets:
            count += 1
            detector.process_packet(packet)

    print(f"Analise concluida: {count} pacote(s) processado(s).")


def resolve_direction(direction: str | None, using_live_capture: bool) -> Direction:
    if direction is not None:
        return direction  # type: ignore[return-value]
    return "inbound" if using_live_capture else "both"


def resolve_local_networks(interface_name: str | None) -> tuple[ipaddress._BaseNetwork, ...]:
    if not interface_name:
        return ()
    return tuple(dict.fromkeys(_interface_networks(interface_name)))


def _interface_networks(interface_name: str) -> list[ipaddress._BaseNetwork]:
    networks = []
    for interface in get_interfaces():
        if interface.name != interface_name:
            continue
        for value in interface.ips:
            network = _try_parse_network(value)
            if network is not None:
                networks.append(network)
    return networks


def _try_parse_network(value: str) -> ipaddress._BaseNetwork | None:
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        return None
