from __future__ import annotations

from scapy.layers.inet import ICMP, IP, TCP, UDP

from .detector import PortScanDetector


def run_demo_scenario(detector: PortScanDetector) -> int:
    packets = []
    packets.extend(_remote_access_progression())
    packets.extend(_database_horizontal_sweep())
    packets.extend(_distributed_platform_recon())
    packets.extend(_slow_web_recon())
    packets.extend(_udp_network_probe())

    for packet in packets:
        detector.process_packet(packet)

    return len(packets)


def _remote_access_progression() -> list[object]:
    source = "192.168.56.20"
    target = "10.10.10.25"
    base_time = 10_000.0
    packets = []

    for index, port in enumerate((22, 3389, 445, 5985)):
        sport = 43000 + index
        packets.append(_tcp_packet(source, target, sport, port, "S", base_time + index * 2))
        if port in (22, 3389):
            packets.append(_tcp_packet(target, source, port, sport, "SA", base_time + index * 2 + 0.1))
        if port == 3389:
            packets.append(_tcp_packet(source, target, sport, port, "A", base_time + index * 2 + 0.2))
        if port == 445:
            packets.append(_tcp_packet(target, source, port, sport, "RA", base_time + index * 2 + 0.1))

    return packets


def _database_horizontal_sweep() -> list[object]:
    source = "203.0.113.44"
    base_time = 10_100.0
    packets = []

    for index, target in enumerate(("10.10.20.10", "10.10.20.11", "10.10.20.12", "10.10.20.13")):
        packets.append(_tcp_packet(source, target, 44000 + index, 6379, "S", base_time + index))

    return packets


def _distributed_platform_recon() -> list[object]:
    target = "10.10.30.15"
    base_time = 10_200.0
    packets = []

    for index, source in enumerate(("198.51.100.10", "198.51.100.11", "198.51.100.12", "198.51.100.13")):
        sport = 45000 + index
        packets.append(_tcp_packet(source, target, sport, 6443, "S", base_time + index))
        if index == 1:
            packets.append(_tcp_packet(target, source, 6443, sport, "SA", base_time + index + 0.1))

    return packets


def _slow_web_recon() -> list[object]:
    source = "10.10.50.90"
    target = "10.10.40.30"
    base_time = 10_300.0
    ports = (80, 443, 8000, 8080, 8443, 8888, 5601, 9200, 9300, 10250, 10255, 2379)

    return [
        _tcp_packet(source, target, 46000 + index, port, "S", base_time + index * 45)
        for index, port in enumerate(ports)
    ]


def _udp_network_probe() -> list[object]:
    source = "172.16.1.77"
    target = "10.10.60.5"
    base_time = 11_000.0
    packets = []

    for index, port in enumerate((53, 123, 161, 47808)):
        sport = 47000 + index
        packets.append(_udp_packet(source, target, sport, port, base_time + index))
        if port in (161, 47808):
            packets.append(_icmp_port_unreachable(target, source, sport, port, base_time + index + 0.1))

    return packets


def _tcp_packet(source: str, target: str, sport: int, dport: int, flags: str, timestamp: float) -> object:
    packet = IP(src=source, dst=target) / TCP(sport=sport, dport=dport, flags=flags)
    packet.time = timestamp
    return packet


def _udp_packet(source: str, target: str, sport: int, dport: int, timestamp: float) -> object:
    packet = IP(src=source, dst=target) / UDP(sport=sport, dport=dport)
    packet.time = timestamp
    return packet


def _icmp_port_unreachable(
    responder: str,
    original_source: str,
    original_sport: int,
    original_dport: int,
    timestamp: float,
) -> object:
    packet = (
        IP(src=responder, dst=original_source)
        / ICMP(type=3, code=3)
        / IP(src=original_source, dst=responder)
        / UDP(sport=original_sport, dport=original_dport)
    )
    packet.time = timestamp
    return packet
