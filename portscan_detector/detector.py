from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
from typing import Callable, Deque, Dict, Literal, Optional, Set, Tuple

from scapy.layers.inet import ICMP, IP, TCP, UDP

from .intelligence import (
    EXPOSURE_ATTEMPTED,
    EXPOSURE_CLOSED,
    EXPOSURE_OPEN,
    AttackHypothesis,
    ServiceFinding,
    build_service_findings,
    infer_hypothesis,
    service_to_label,
)


VerticalKey = Tuple[str, str, str]
HorizontalKey = Tuple[str, int, str]
DistributedKey = Tuple[str, int, str]
FlowKey = Tuple[str, str, int]
CooldownKey = Tuple[str, str, int, str]
Direction = Literal["inbound", "outbound", "both"]
ProbeKey = Tuple[str, str, int, str]


SYN_SCAN = "syn_scan"
TCP_CONNECT_SCAN = "tcp_connect_scan"
FIN_SCAN = "fin_scan"
NULL_SCAN = "null_scan"
XMAS_SCAN = "xmas_scan"
ACK_SCAN = "ack_scan"
UDP_SCAN = "udp_scan"
HORIZONTAL_SCAN = "horizontal_scan"
DISTRIBUTED_SCAN = "distributed_scan"
SLOW_SCAN = "slow_scan"


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
    protocol: str
    sources: tuple[str, ...]
    targets: tuple[str, ...]
    services: tuple[ServiceFinding, ...]
    service_categories: tuple[str, ...]
    hypothesis: str
    intent: str
    severity: str
    confidence: float
    risk_score: int
    mitre_technique: str
    evidence: tuple[str, ...]
    recommendations: tuple[str, ...]
    campaign_id: str
    criticality: int = 0
    criticality_reasons: tuple[str, ...] = ()

    @property
    def port_count(self) -> int:
        return len(self.ports)

    @property
    def duration_seconds(self) -> float:
        duration = (self.last_seen - self.first_seen).total_seconds()
        return max(duration, 0.0)

    @property
    def packets_per_second(self) -> float:
        duration = self.duration_seconds
        if duration <= 0:
            return float(self.packet_count)
        return self.packet_count / duration

    @property
    def open_services(self) -> tuple[ServiceFinding, ...]:
        return tuple(service for service in self.services if service.exposure == EXPOSURE_OPEN)


@dataclass(frozen=True)
class ScanAttempt:
    timestamp: float
    source_ip: str
    target_ip: str
    destination_port: int
    scan_type: str
    protocol: str


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
        print_events: bool = True,
    ) -> None:
        if threshold < 2:
            raise ValueError("threshold deve ser pelo menos 2")
        if window_seconds <= 0:
            raise ValueError("window_seconds deve ser maior que zero")
        if cooldown_seconds < 0:
            raise ValueError("cooldown_seconds não pode ser negativo")
        if direction not in {"inbound", "outbound", "both"}:
            raise ValueError("direction deve ser inbound, outbound ou both")

        self.threshold = threshold
        self.window_seconds = window_seconds
        self.cooldown_seconds = cooldown_seconds
        self.slow_window_seconds = max(window_seconds * 30, 600.0)
        self.slow_threshold = max(threshold * 3, threshold + 8)
        self.on_event = on_event
        self.assess_event = assess_event
        self.alert_threshold = max(0, min(100, alert_threshold))
        self.direction = direction
        self.local_networks = local_networks
        self.print_events = print_events

        self._vertical_attempts: Dict[VerticalKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._horizontal_attempts: Dict[HorizontalKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._distributed_attempts: Dict[DistributedKey, Deque[ScanAttempt]] = defaultdict(deque)
        self._slow_vertical_attempts: Dict[VerticalKey, Deque[ScanAttempt]] = defaultdict(deque)

        self._pending_connect_flows: Dict[FlowKey, float] = {}
        self._established_flows: Set[FlowKey] = set()
        self._known_probe_keys: Set[ProbeKey] = set()
        self._service_states: Dict[ProbeKey, str] = {}
        self._post_scan_connections: Set[ProbeKey] = set()
        self._last_alert_at: Dict[CooldownKey, float] = {}
        self._campaign_keys: Dict[str, str] = {}
        self._campaign_counter = 0

    def process_packet(self, packet: object) -> Optional[PortScanEvent]:
        self._update_response_state(packet)
        self._detect_post_probe_connection(packet)

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
            if self.print_events:
                self._print_event(event)

        return assessed_events[0] if assessed_events else None

    def _process_attempt(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        self._register_probe(attempt)

        events = []
        events.extend(self._detect_vertical(attempt))
        events.extend(self._detect_horizontal(attempt))
        events.extend(self._detect_distributed(attempt))
        events.extend(self._detect_slow_vertical(attempt))
        return events

    def _detect_vertical(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        key = (attempt.source_ip, attempt.target_ip, attempt.scan_type)
        attempts = self._vertical_attempts[key]
        attempts.append(attempt)
        self._remove_expired(attempts, attempt.timestamp, self.window_seconds)

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
        self._remove_expired(attempts, attempt.timestamp, self.window_seconds)

        targets = {item.target_ip for item in attempts}
        if len(targets) < self.threshold:
            return []

        cooldown_key = (
            attempt.source_ip,
            "*",
            attempt.destination_port,
            f"{attempt.scan_type}:{HORIZONTAL_SCAN}",
        )
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
        self._remove_expired(attempts, attempt.timestamp, self.window_seconds)

        sources = {item.source_ip for item in attempts}
        if len(sources) < self.threshold:
            return []

        cooldown_key = (
            "*",
            attempt.target_ip,
            attempt.destination_port,
            f"{attempt.scan_type}:{DISTRIBUTED_SCAN}",
        )
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

    def _detect_slow_vertical(self, attempt: ScanAttempt) -> list[PortScanEvent]:
        key = (attempt.source_ip, attempt.target_ip, attempt.scan_type)
        attempts = self._slow_vertical_attempts[key]
        attempts.append(attempt)
        self._remove_expired(attempts, attempt.timestamp, self.slow_window_seconds)

        ports = self._ports(attempts)
        if len(ports) < self.slow_threshold:
            return []
        if attempts[-1].timestamp - attempts[0].timestamp < self.window_seconds:
            return []

        cooldown_key = (attempt.source_ip, attempt.target_ip, 0, f"{attempt.scan_type}:{SLOW_SCAN}")
        if self._in_cooldown(cooldown_key, attempt.timestamp):
            return []

        self._last_alert_at[cooldown_key] = attempt.timestamp
        return [
            self._build_event(
                attempts=attempts,
                source_ip=attempt.source_ip,
                target_ip=attempt.target_ip,
                ports=ports,
                scan_types={attempt.scan_type, SLOW_SCAN},
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
        protocol = self._dominant_protocol(attempts)
        sources = tuple(sorted({attempt.source_ip for attempt in attempts}))
        targets = tuple(sorted({attempt.target_ip for attempt in attempts}))
        exposure_by_port = self._exposure_by_port(attempts, ports, protocol)
        services = build_service_findings(ports, protocol, exposure_by_port)
        post_scan_connection_observed = self._has_post_scan_connection(attempts)
        first_seen = datetime.fromtimestamp(attempts[0].timestamp, tz=timezone.utc)
        last_seen = datetime.fromtimestamp(attempts[-1].timestamp, tz=timezone.utc)
        duration_seconds = max((last_seen - first_seen).total_seconds(), 0.0)

        hypothesis = infer_hypothesis(
            scan_types=tuple(sorted(scan_types)),
            services=services,
            source_count=len(sources),
            target_count=len(targets),
            packet_count=len(attempts),
            duration_seconds=duration_seconds,
            threshold=self.threshold,
            post_scan_connection_observed=post_scan_connection_observed,
        )
        campaign_id = self._campaign_id_for(
            source_ip=source_ip,
            target_ip=target_ip,
            ports=ports,
            scan_types=scan_types,
        )

        return self._event_from_hypothesis(
            hypothesis=hypothesis,
            first_seen=first_seen,
            last_seen=last_seen,
            source_ip=source_ip,
            target_ip=target_ip,
            ports=tuple(sorted(ports)),
            packet_count=len(attempts),
            scan_types=tuple(sorted(scan_types)),
            protocol=protocol,
            sources=sources,
            targets=targets,
            services=services,
            campaign_id=campaign_id,
        )

    def _event_from_hypothesis(
        self,
        hypothesis: AttackHypothesis,
        first_seen: datetime,
        last_seen: datetime,
        source_ip: str,
        target_ip: str,
        ports: tuple[int, ...],
        packet_count: int,
        scan_types: tuple[str, ...],
        protocol: str,
        sources: tuple[str, ...],
        targets: tuple[str, ...],
        services: tuple[ServiceFinding, ...],
        campaign_id: str,
    ) -> PortScanEvent:
        return PortScanEvent(
            detected_at=datetime.now(tz=timezone.utc),
            first_seen=first_seen,
            last_seen=last_seen,
            source_ip=source_ip,
            target_ip=target_ip,
            ports=ports,
            packet_count=packet_count,
            scan_types=scan_types,
            protocol=protocol,
            sources=sources,
            targets=targets,
            services=services,
            service_categories=hypothesis.service_categories,
            hypothesis=hypothesis.title,
            intent=hypothesis.intent,
            severity=hypothesis.severity,
            confidence=hypothesis.confidence,
            risk_score=hypothesis.risk_score,
            mitre_technique=hypothesis.mitre_technique,
            evidence=hypothesis.evidence,
            recommendations=hypothesis.recommendations,
            campaign_id=campaign_id,
        )

    def _packet_to_attempt(self, packet: object) -> Optional[ScanAttempt]:
        if IP not in packet:  # type: ignore[operator]
            return None
        if ICMP in packet:  # type: ignore[operator]
            return None
        if self._is_known_tcp_response(packet):
            return None

        timestamp = float(getattr(packet, "time", datetime.now(tz=timezone.utc).timestamp()))
        ip_layer = packet[IP]  # type: ignore[index]
        source_ip = str(ip_layer.src)
        target_ip = str(ip_layer.dst)
        if not self._matches_direction(source_ip, target_ip):
            return None

        if TCP in packet:  # type: ignore[operator]
            tcp_layer = packet[TCP]  # type: ignore[index]
            port = int(tcp_layer.dport)
            scan_type = self._classify_tcp_packet(packet, timestamp)
            if scan_type is None:
                return None
            return ScanAttempt(timestamp, source_ip, target_ip, port, scan_type, "tcp")

        if UDP in packet:  # type: ignore[operator]
            udp_layer = packet[UDP]  # type: ignore[index]
            return ScanAttempt(timestamp, source_ip, target_ip, int(udp_layer.dport), UDP_SCAN, "udp")

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
        ip_layer = packet[IP]  # type: ignore[index]
        tcp_layer = packet[TCP]  # type: ignore[index]
        flags = int(tcp_layer.flags)
        source_ip = str(ip_layer.src)
        target_ip = str(ip_layer.dst)
        port = int(tcp_layer.dport)

        fin = 0x01
        syn = 0x02
        rst = 0x04
        psh = 0x08
        ack = 0x10
        urg = 0x20

        flow_key = (source_ip, target_ip, port)
        if flow_key in self._established_flows and flags & ack:
            return None
        if flags & rst or flags & syn and flags & ack:
            return None

        if flags == 0:
            return NULL_SCAN
        if flags & fin and not flags & (syn | ack | psh | urg):
            return FIN_SCAN
        if flags & fin and flags & psh and flags & urg and not flags & (syn | ack):
            return XMAS_SCAN
        if flags == ack:
            if self._recent_pending_connect(flow_key, timestamp):
                self._established_flows.add(flow_key)
                return TCP_CONNECT_SCAN
            return ACK_SCAN
        if flags & syn and not flags & ack:
            self._pending_connect_flows[flow_key] = timestamp
            return SYN_SCAN

        return None

    def _update_response_state(self, packet: object) -> None:
        self._update_tcp_response_state(packet)
        self._update_udp_response_state(packet)

    def _update_tcp_response_state(self, packet: object) -> None:
        if IP not in packet or TCP not in packet:  # type: ignore[operator]
            return

        ip_layer = packet[IP]  # type: ignore[index]
        tcp_layer = packet[TCP]  # type: ignore[index]
        flags = int(tcp_layer.flags)
        syn = 0x02
        rst = 0x04
        ack = 0x10
        key = (str(ip_layer.dst), str(ip_layer.src), int(tcp_layer.sport), "tcp")

        if key not in self._known_probe_keys:
            return
        if flags & syn and flags & ack:
            self._service_states[key] = EXPOSURE_OPEN
        elif flags & rst:
            self._service_states[key] = EXPOSURE_CLOSED

    def _update_udp_response_state(self, packet: object) -> None:
        if IP not in packet or ICMP not in packet:  # type: ignore[operator]
            return

        icmp_layer = packet[ICMP]  # type: ignore[index]
        if int(getattr(icmp_layer, "type", -1)) != 3 or int(getattr(icmp_layer, "code", -1)) != 3:
            return

        inner_packet = icmp_layer.payload
        if IP not in inner_packet or UDP not in inner_packet:  # type: ignore[operator]
            return

        inner_ip = inner_packet[IP]  # type: ignore[index]
        inner_udp = inner_packet[UDP]  # type: ignore[index]
        key = (str(inner_ip.src), str(inner_ip.dst), int(inner_udp.dport), "udp")
        if key in self._known_probe_keys:
            self._service_states[key] = EXPOSURE_CLOSED

    def _detect_post_probe_connection(self, packet: object) -> None:
        if IP not in packet or TCP not in packet:  # type: ignore[operator]
            return

        ip_layer = packet[IP]  # type: ignore[index]
        tcp_layer = packet[TCP]  # type: ignore[index]
        flags = int(tcp_layer.flags)
        ack = 0x10
        syn = 0x02
        key = (str(ip_layer.src), str(ip_layer.dst), int(tcp_layer.dport), "tcp")

        if not flags & ack or flags & syn:
            return
        if self._service_states.get(key) == EXPOSURE_OPEN:
            self._post_scan_connections.add(key)

    def _register_probe(self, attempt: ScanAttempt) -> None:
        key = self._probe_key(attempt)
        self._known_probe_keys.add(key)
        self._service_states.setdefault(key, EXPOSURE_ATTEMPTED)

    def _probe_key(self, attempt: ScanAttempt) -> ProbeKey:
        return (
            attempt.source_ip,
            attempt.target_ip,
            attempt.destination_port,
            attempt.protocol,
        )

    def _is_known_tcp_response(self, packet: object) -> bool:
        if IP not in packet or TCP not in packet:  # type: ignore[operator]
            return False

        ip_layer = packet[IP]  # type: ignore[index]
        tcp_layer = packet[TCP]  # type: ignore[index]
        key = (str(ip_layer.dst), str(ip_layer.src), int(tcp_layer.sport), "tcp")
        return key in self._known_probe_keys

    def _recent_pending_connect(self, flow_key: FlowKey, timestamp: float) -> bool:
        started_at = self._pending_connect_flows.get(flow_key)
        return started_at is not None and timestamp - started_at <= self.window_seconds

    def _exposure_by_port(
        self,
        attempts: Deque[ScanAttempt],
        ports: Set[int],
        protocol: str,
    ) -> dict[int, str]:
        exposure_by_port: dict[int, str] = {}
        for port in ports:
            states = {
                self._service_states.get(self._probe_key(attempt), EXPOSURE_ATTEMPTED)
                for attempt in attempts
                if attempt.destination_port == port and attempt.protocol == protocol
            }
            if EXPOSURE_OPEN in states:
                exposure_by_port[port] = EXPOSURE_OPEN
            elif EXPOSURE_CLOSED in states:
                exposure_by_port[port] = EXPOSURE_CLOSED
            else:
                exposure_by_port[port] = EXPOSURE_ATTEMPTED
        return exposure_by_port

    def _has_post_scan_connection(self, attempts: Deque[ScanAttempt]) -> bool:
        return any(self._probe_key(attempt) in self._post_scan_connections for attempt in attempts)

    def _campaign_id_for(
        self,
        source_ip: str,
        target_ip: str,
        ports: Set[int],
        scan_types: Set[str],
    ) -> str:
        port_key = ",".join(str(port) for port in sorted(ports))
        if DISTRIBUTED_SCAN in scan_types:
            campaign_key = f"distributed:{target_ip}:{port_key}"
        elif HORIZONTAL_SCAN in scan_types:
            campaign_key = f"horizontal:{source_ip}:{port_key}"
        else:
            campaign_key = f"vertical:{source_ip}:{target_ip}"

        existing = self._campaign_keys.get(campaign_key)
        if existing is not None:
            return existing

        self._campaign_counter += 1
        campaign_id = f"ID-{self._campaign_counter:04d}"
        self._campaign_keys[campaign_key] = campaign_id
        return campaign_id

    def _print_event(self, event: PortScanEvent) -> None:
        priority_score = max(event.risk_score, event.criticality)
        is_alert = priority_score >= self.alert_threshold
        prefix = "ALERTA" if is_alert else event.severity.upper()
        header = (
            f"[{prefix}] {event.hypothesis} | risco={event.risk_score}/100 "
            f"| criticidade={event.criticality}/100 | confiança={event.confidence:.0%}"
        )
        if is_alert:
            header = f"\033[31m{header}\033[0m"
        print(header)
        print(
            f"  Campanha: {event.campaign_id} | Origem: {event.source_ip} | "
            f"Destino: {event.target_ip} | Protocolo: {event.protocol.upper()}"
        )
        print(f"  Intenção provável: {event.intent}")
        if event.services:
            services = ", ".join(service_to_label(service) for service in event.services[:8])
            print(f"  Serviços avaliados: {services}")
        if event.evidence:
            print(f"  Evidência principal: {event.evidence[0]}")
        if event.criticality_reasons:
            print(f"  Criticidade: {'; '.join(event.criticality_reasons)}")
        print(f"  MITRE: {event.mitre_technique}")

    def _remove_expired(self, attempts: Deque[ScanAttempt], now: float, window_seconds: float) -> None:
        while attempts and now - attempts[0].timestamp > window_seconds:
            attempts.popleft()

    def _in_cooldown(self, key: CooldownKey, now: float) -> bool:
        last_alert_at = self._last_alert_at.get(key)
        return last_alert_at is not None and now - last_alert_at < self.cooldown_seconds

    @staticmethod
    def _ports(attempts: Deque[ScanAttempt]) -> Set[int]:
        return {attempt.destination_port for attempt in attempts}

    @staticmethod
    def _dominant_protocol(attempts: Deque[ScanAttempt]) -> str:
        protocols = {attempt.protocol for attempt in attempts}
        if len(protocols) == 1:
            return next(iter(protocols))
        return "mixed"
