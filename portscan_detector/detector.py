from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Callable, Deque, Dict, Literal, Optional, Set, Tuple

from scapy.layers.inet import IP, TCP, UDP


VerticalKey = Tuple[str, str, str]
HorizontalKey = Tuple[str, int, str]
DistributedKey = Tuple[str, int, str]
FlowKey = Tuple[str, str, int]
CooldownKey = Tuple[str, str, int, str]
Direction = Literal["inbound", "outbound", "both"]


SYN_SCAN = "syn_scan"
TCP_CONNECT_SCAN = "tcp_connect_scan"
FIN_SCAN = "fin_scan"
NULL_SCAN = "null_scan"
XMAS_SCAN = "xmas_scan"
ACK_SCAN = "ack_scan"
UDP_SCAN = "udp_scan"
HORIZONTAL_SCAN = "horizontal_scan"
DISTRIBUTED_SCAN = "distributed_scan"


@dataclass(frozen=True)
class PortScanEvent:
    detected_at: datetime
    first_seen: datetime
    last_seen: datetime
    source_ip: str
    target_ip: str
    ports: tuple[int, ...]
    packet_count: int
    scan_types: tuple[str, ...]
    criticality: int = 0
    criticality_reasons: tuple[str, ...] = ()

    @property
    def port_count(self) -> int:
        return len(self.ports)


@dataclass(frozen=True)
class ScanAttempt:
    timestamp: float
    source_ip: str
    target_ip: str
    destination_port: int
    scan_type: str


class PortScanDetector:
    def __init__(
        self,
        threshold: int,
        window_seconds: float,
        cooldown_seconds: float,
        on_event: Callable[[PortScanEvent], None],
        assess_event: Callable[[PortScanEvent], PortScanEvent] | None = None,
        alert_threshold: int = 60,
        direction: Direction = "both",
        local_networks: tuple[ipaddress._BaseNetwork, ...] = (),
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold deve ser pelo menos 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds deve ser maior que zero")
        if direction not in {"inbound", "outbound", "both"}:
            raise ValueError("direction deve ser inbound, outbound ou both")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.on_event = on_event
        self.assess_event = assess_event
        self.alert_threshold = max(0, min(100, alert_threshold))
        self.direction = direction
        self.local_networks = local_networks
        self._vertical_attempts: Dict[VerticalKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._horizontal_attempts: Dict[HorizontalKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._distributed_attempts: Dict[DistributedKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._pending_connect_flows: Dict[FlowKey, float] = {}
        self._last_alert_at: Dict[CooldownKey, float] = {}

    def process_packet(self, packet: object) -> Optional[PortScanEvent]:
        attempt = self._packet_to_attempt(packet)
        if attempt is None:
            return None

        events = self._process_attempt(attempt)
        assessed_events = []
        for event in events:
            if self.assess_event is not None:
                event = self.assess_event(event)
            assessed_events.append(event)
            self.on_event(event)
            self._print_event(event)

        return assessed_events[0] if assessed_events else None

    def _print_event(self, event: PortScanEvent) -> None:
        is_alert = event.criticality >= self.alert_threshold
        prefix = "ALERTA port scan" if is_alert else "Possivel port scan"
        message = (
            f"{prefix}: "
            f"{event.source_ip} -> {event.target_ip} "
            f"criticidade={event.criticality}/100 "
            f"tipos={','.join(event.scan_types)} "
            f"portas={','.join(str(port) for port in event.ports)} "
            f"janela={self.window_seconds:g}s"
        )
        if event.criticality_reasons:
            message += f" motivos={'; '.join(event.criticality_reasons)}"
        if is_alert:
            message = f"\033[31m{message}\033[0m"
        print(message)

    def _process_attempt(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        events = []
        events.extend(self._detect_vertical(attempt))
        events.extend(self._detect_horizontal(attempt))
        events.extend(self._detect_distributed(attempt))
        return events

    def _detect_vertical(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        key = (attempt.source_ip, attempt.target_ip, attempt.scan_type)
        attempts = self._vertical_attempts[key]
        attempts.append(attempt)
        self._remove_expired(attempts, attempt.timestamp)

        ports = self._ports(attempts)
        if len(ports) < self.threshold:
            return []

        cooldown_key = (attempt.source_ip, attempt.target_ip, 0, attempt.scan_type)
        if self._in_cooldown(cooldown_key, attempt.timestamp):
            return []

        self._last_alert_at[cooldown_key] = attempt.timestamp
        return [
            self._build_event(
                attempts=attempts,
                source_ip=attempt.source_ip,
                target_ip=attempt.target_ip,
                ports=ports,
                scan_types={attempt.scan_type},
            )
        ]

    def _detect_horizontal(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        key = (attempt.source_ip, attempt.destination_port, attempt.scan_type)
        attempts = self._horizontal_attempts[key]
        attempts.append(attempt)
        self._remove_expired(attempts, attempt.timestamp)

        targets = {item.target_ip for item in attempts}
        if len(targets) < self.threshold:
            return []

        cooldown_key = (attempt.source_ip, "*", attempt.destination_port, f"{attempt.scan_type}:{HORIZONTAL_SCAN}")
        if self._in_cooldown(cooldown_key, attempt.timestamp):
            return []

        self._last_alert_at[cooldown_key] = attempt.timestamp
        return [
            self._build_event(
                attempts=attempts,
                source_ip=attempt.source_ip,
                target_ip="*",
                ports={attempt.destination_port},
                scan_types={attempt.scan_type, HORIZONTAL_SCAN},
            )
        ]

    def _detect_distributed(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        key = (attempt.target_ip, attempt.destination_port, attempt.scan_type)
        attempts = self._distributed_attempts[key]
        attempts.append(attempt)
        self._remove_expired(attempts, attempt.timestamp)

        sources = {item.source_ip for item in attempts}
        if len(sources) < self.threshold:
            return []

        cooldown_key = ("*", attempt.target_ip, attempt.destination_port, f"{attempt.scan_type}:{DISTRIBUTED_SCAN}")
        if self._in_cooldown(cooldown_key, attempt.timestamp):
            return []

        self._last_alert_at[cooldown_key] = attempt.timestamp
        return [
            self._build_event(
                attempts=attempts,
                source_ip="*",
                target_ip=attempt.target_ip,
                ports={attempt.destination_port},
                scan_types={attempt.scan_type, DISTRIBUTED_SCAN},
            )
        ]

    def _build_event(
        self,
        attempts: Deque[ScanAttempt],
        source_ip: str,
        target_ip: str,
        ports: Set[int],
        scan_types: Set[str],
    ) -> PortScanEvent:
        return PortScanEvent(
            detected_at=datetime.now(tz=timezone.utc),
            first_seen=datetime.fromtimestamp(attempts[0].timestamp, tz=timezone.utc),
            last_seen=datetime.fromtimestamp(attempts[-1].timestamp, tz=timezone.utc),
            source_ip=source_ip,
            target_ip=target_ip,
            ports=tuple(sorted(ports)),
            packet_count=len(attempts),
            scan_types=tuple(sorted(scan_types)),
        )

    def _packet_to_attempt(self, packet: object) -> Optional[ScanAttempt]:
        if IP not in packet:  # type: ignore
            return None

        timestamp = float(getattr(packet, "time", datetime.now(tz=timezone.utc).timestamp()))
        ip_layer = packet[IP]  # type: ignore
        source_ip = str(ip_layer.src)
        target_ip = str(ip_layer.dst)
        if not self._matches_direction(source_ip, target_ip):
            return None

        if TCP in packet:  # type: ignore
            tcp_layer = packet[TCP]  # type: ignore
            port = int(tcp_layer.dport)
            scan_type = self._classify_tcp_packet(packet, timestamp)
            if scan_type is None:
                return None
            return ScanAttempt(timestamp, source_ip, target_ip, port, scan_type)

        if UDP in packet:  # type: ignore
            udp_layer = packet[UDP]  # type: ignore
            return ScanAttempt(timestamp, source_ip, target_ip, int(udp_layer.dport), UDP_SCAN)

        return None

    def _matches_direction(self, source_ip: str, target_ip: str) -> bool:
        if self.direction == "both":
            return True
        if not self.local_networks:
            return True

        source_is_local = self._ip_in_local_networks(source_ip)
        target_is_local = self._ip_in_local_networks(target_ip)
        if self.direction == "inbound":
            return target_is_local and not source_is_local
        if self.direction == "outbound":
            return source_is_local and not target_is_local
        return True

    def _ip_in_local_networks(self, ip: str) -> bool:
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in self.local_networks)

    def _classify_tcp_packet(self, packet: object, timestamp: float) -> Optional[str]:
        ip_layer = packet[IP]  # type: ignore
        tcp_layer = packet[TCP]  # type: ignore
        flags = int(tcp_layer.flags)
        source_ip = str(ip_layer.src)
        target_ip = str(ip_layer.dst)
        port = int(tcp_layer.dport)

        fin = 0x01
        syn = 0x02
        psh = 0x08
        ack = 0x10
        urg = 0x20

        if flags == 0:
            return NULL_SCAN
        if flags & fin and not flags & (syn | ack | psh | urg):
            return FIN_SCAN
        if flags & fin and flags & psh and flags & urg and not flags & (syn | ack):
            return XMAS_SCAN
        if flags == ack:
            flow_key = (source_ip, target_ip, port)
            if self._recent_pending_connect(flow_key, timestamp):
                return TCP_CONNECT_SCAN
            return ACK_SCAN
        if flags & syn and not flags & ack:
            self._pending_connect_flows[(source_ip, target_ip, port)] = timestamp
            return SYN_SCAN

        return None

    def _recent_pending_connect(self, flow_key: FlowKey, timestamp: float) -> bool:
        started_at = self._pending_connect_flows.get(flow_key)
        return started_at is not None and timestamp - started_at <= self.window_seconds

    def _remove_expired(self, attempts: Deque[ScanAttempt], now: float) -> None:
        while attempts and now - attempts[0].timestamp > self.window_seconds:
            attempts.popleft()

    def _in_cooldown(self, key: CooldownKey, now: float) -> bool:
        last_alert_at = self._last_alert_at.get(key)
        return last_alert_at is not None and now - last_alert_at < self.cooldown_seconds

    @staticmethod
    def _ports(attempts: Deque[ScanAttempt]) -> Set[int]:
        return {attempt.destination_port for attempt in attempts}
