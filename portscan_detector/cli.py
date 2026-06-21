from __future__ import annotations

import argparse
from pathlib import Path

from scapy.all import sniff
from scapy.utils import PcapReader

from .detector import PortScanDetector
from .interface_listing import format_interface_names, print_interfaces
from .storage import SQLiteEventStore


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Detecta possiveis port scans TCP SYN e salva eventos em SQLite."
    )
    source = parser.add_mutually_exclusive_group(required=True)
    source.add_argument("--pcap", type=Path, help="Arquivo .pcap/.pcapng para analisar.")
    source.add_argument("--interface", help="Interface de rede para captura ao vivo.")
    source.add_argument(
        "--list-interfaces",
        action="store_true",
        help="Lista interfaces conhecidas pelo Scapy e encerra.",
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
        default=20.0,
        help="Janela de tempo em segundos. Padrao: 20",
    )
    parser.add_argument(
        "--cooldown",
        type=float,
        default=60.0,
        help="Tempo minimo entre alertas repetidos do mesmo par origem/destino. Padrao: 60",
    )
    parser.add_argument(
        "--bpf",
        default="tcp",
        help="Filtro BPF usado na captura ao vivo. Padrao: tcp",
    )
    return parser


def main() -> None:
    args = build_parser().parse_args()

    if args.list_interfaces:
        print_interfaces()
        return

    store = SQLiteEventStore(args.database)
    detector = PortScanDetector(
        threshold=args.threshold,
        window_seconds=args.window,
        cooldown_seconds=args.cooldown,
        on_event=store.save,
    )

    if args.pcap:
        analyze_pcap(args.pcap, detector)
        return

    print(f"Capturando na interface {args.interface!r}. Pressione Ctrl+C para parar.")
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
                "Captura ao vivo indisponivel: o Scapy nao encontrou WinPcap/Npcap.\n"
                "No Windows, instale o Npcap, marque a opcao de compatibilidade "
                "com WinPcap durante a instalacao e execute o terminal como "
                "administrador. Depois rode novamente com --list-interfaces para "
                "confirmar o nome da interface."
            ) from error
        raise
    except ValueError as error:
        message = str(error).lower()
        if "interface" in message and "not found" in message:
            raise SystemExit(
                f"Interface nao encontrada: {args.interface!r}\n\n"
                f"{format_interface_names()}\n\n"
                "Rode `python -m portscan_detector --list-interfaces` "
                "para ver mais detalhes."
            ) from error
        raise


def analyze_pcap(path: Path, detector: PortScanDetector) -> None:
    if not path.exists():
        raise SystemExit(f"Arquivo nao encontrado: {path}")

    count = 0
    with PcapReader(str(path)) as packets:
        for packet in packets:
            count += 1
            detector.process_packet(packet)

    print(f"Analise concluida: {count} pacote(s) processado(s).")
