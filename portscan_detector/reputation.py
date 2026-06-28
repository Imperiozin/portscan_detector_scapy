from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from .detector import (
    ACK_SCAN,
    DISTRIBUTED_SCAN,
    FIN_SCAN,
    HORIZONTAL_SCAN,
    NULL_SCAN,
    PortScanEvent,
    UDP_SCAN,
    XMAS_SCAN,
)


DEFAULT_ABUSEIPDB_KEY = (
    "a17960f15e5b25eda2f4a324c757db98fb74122ff4607b1e90aabd3eab61b222279f28c944b11194"
)


@dataclass(frozen=True)
class ReputationInfo:
    ip: str
    country: str = ""
    asn: str = ""
    organization: str = ""
    abuse_score: int | None = None
    crowdsec_listed: bool = False
    greynoise_classification: str = ""
    greynoise_noise: bool = False
    greynoise_riot: bool = False
    errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class MatchRules:
    ips: tuple[ipaddress._BaseNetwork, ...] = ()
    source_ips: tuple[ipaddress._BaseNetwork, ...] = ()
    target_ips: tuple[ipaddress._BaseNetwork, ...] = ()
    countries: frozenset[str] = frozenset()
    asns: frozenset[str] = frozenset()
    organizations: tuple[str, ...] = ()
    ports: frozenset[int] = frozenset()
    scan_types: frozenset[str] = frozenset()

    @classmethod
    def from_file(cls, path: Path | None) -> "MatchRules":
        if path is None or not path.exists():
            return cls()
        with path.open("r", encoding="utf-8") as file:
            payload = json.load(file)
        if not isinstance(payload, dict):
            raise ValueError(f"{path} deve conter um objeto JSON")
        return cls(
            ips=_parse_networks(payload.get("ips", ())),
            source_ips=_parse_networks(payload.get("source_ips", ())),
            target_ips=_parse_networks(payload.get("target_ips", ())),
            countries=frozenset(_normalize_country(item) for item in _as_list(payload.get("countries", ()))),
            asns=frozenset(_normalize_asn(item) for item in _as_list(payload.get("asns", ()))),
            organizations=tuple(str(item).lower() for item in _as_list(payload.get("organizations", ()))),
            ports=frozenset(int(item) for item in _as_list(payload.get("ports", ()))), # type: ignore
            scan_types=frozenset(str(item) for item in _as_list(payload.get("scan_types", ()))),
        )

    def matches(
        self,
        event: PortScanEvent,
        source_reputation: ReputationInfo | None,
        target_reputation: ReputationInfo | None,
    ) -> list[str]:
        reasons: list[str] = []
        if self._ip_matches(event.source_ip, self.ips) or self._ip_matches(event.target_ip, self.ips):
            reasons.append("ip")
        if self._ip_matches(event.source_ip, self.source_ips):
            reasons.append("source_ip")
        if self._ip_matches(event.target_ip, self.target_ips):
            reasons.append("target_ip")
        if self.ports and any(port in self.ports for port in event.ports):
            reasons.append("port")
        if self.scan_types and any(scan_type in self.scan_types for scan_type in event.scan_types):
            reasons.append("scan_type")
        if self._reputation_matches(source_reputation) or self._reputation_matches(target_reputation):
            reasons.append("reputation")
        return reasons

    def _reputation_matches(self, reputation: ReputationInfo | None) -> bool:
        if reputation is None:
            return False
        if self.countries and _normalize_country(reputation.country) in self.countries:
            return True
        if self.asns and _normalize_asn(reputation.asn) in self.asns:
            return True
        organization = reputation.organization.lower()
        return bool(organization and any(item in organization for item in self.organizations))

    @staticmethod
    def _ip_matches(ip: str, networks: tuple[ipaddress._BaseNetwork, ...]) -> bool:
        if ip == "*" or not networks:
            return False
        try:
            address = ipaddress.ip_address(ip)
        except ValueError:
            return False
        return any(address in network for network in networks)


@dataclass
class CriticalityAssessor:
    whitelist: MatchRules = field(default_factory=MatchRules)
    blacklist: MatchRules = field(default_factory=MatchRules)
    abuseipdb_key: str = DEFAULT_ABUSEIPDB_KEY
    greynoise_key: str = ""
    enable_whois: bool = True
    enable_crowdsec: bool = True
    enable_greynoise: bool = True
    timeout_seconds: float = 3.0

    def __post_init__(self) -> None:
        self._cache: dict[str, ReputationInfo] = {}

    def assess(self, event: PortScanEvent) -> PortScanEvent:
        source_reputation = self._lookup_ip(event.source_ip)
        target_reputation = self._lookup_ip(event.target_ip)
        blacklist_matches = self.blacklist.matches(event, source_reputation, target_reputation)
        whitelist_matches = self.whitelist.matches(event, source_reputation, target_reputation)

        criticality, reasons = self._base_score(event)
        reputation_delta, reputation_reasons = self._reputation_score(source_reputation, "origem")
        criticality += reputation_delta
        reasons.extend(reputation_reasons)

        if blacklist_matches:
            criticality = 100
            reasons.append(f"blacklist:{','.join(blacklist_matches)}")
        elif whitelist_matches:
            criticality = max(0, criticality - 35)
            reasons.append(f"whitelist:{','.join(whitelist_matches)}")

        return replace(
            event,
            criticality=max(0, min(100, criticality)),
            criticality_reasons=tuple(reasons),
        )

    def _base_score(self, event: PortScanEvent) -> tuple[int, list[str]]:
        behavior_score = min(30, event.port_count * 3) + min(20, event.packet_count)
        technical_score = int(getattr(event, "risk_score", 0) or 0)
        score = max(behavior_score, technical_score)
        reasons = [f"comportamento:{behavior_score}"]
        if technical_score:
            reasons.append(f"risco_tecnico:{technical_score}")
        scan_types = set(event.scan_types)
        if HORIZONTAL_SCAN in scan_types:
            score += 10
            reasons.append("horizontal")
        if DISTRIBUTED_SCAN in scan_types:
            score += 20
            reasons.append("distributed")
        if scan_types & {FIN_SCAN, NULL_SCAN, XMAS_SCAN}:
            score += 5
            reasons.append("stealth_tcp")
        if ACK_SCAN in scan_types:
            score += 2
            reasons.append("ack_probe")
        if UDP_SCAN in scan_types:
            score += 2
            reasons.append("udp")
        return min(score, 100), reasons

    def _reputation_score(self, reputation: ReputationInfo | None, label: str) -> tuple[int, list[str]]:
        if reputation is None:
            return 0, []
        score = 0
        reasons: list[str] = []
        if reputation.abuse_score is not None:
            if reputation.abuse_score >= 90:
                score += 35
                reasons.append(f"{label}:abuseipdb>=90")
            elif reputation.abuse_score >= 50:
                score += 25
                reasons.append(f"{label}:abuseipdb>=50")
            elif reputation.abuse_score >= 10:
                score += 10
                reasons.append(f"{label}:abuseipdb>=10")
        if reputation.crowdsec_listed:
            score += 40
            reasons.append(f"{label}:crowdsec")
        if reputation.greynoise_classification in {"malicious", "suspicious"}:
            score += 35 if reputation.greynoise_classification == "malicious" else 20
            reasons.append(f"{label}:greynoise:{reputation.greynoise_classification}")
        elif reputation.greynoise_noise:
            score += 10
            reasons.append(f"{label}:greynoise:noise")
        if reputation.greynoise_riot:
            score -= 20
            reasons.append(f"{label}:greynoise:riot")
        return score, reasons

    def _lookup_ip(self, ip: str) -> ReputationInfo | None:
        if ip == "*":
            return None
        try:
            ipaddress.ip_address(ip)
        except ValueError:
            return None
        if ip not in self._cache:
            self._cache[ip] = self._collect_reputation(ip)
        return self._cache[ip]

    def _collect_reputation(self, ip: str) -> ReputationInfo:
        reputation = ReputationInfo(ip=ip)
        reputation = self._lookup_abuseipdb(reputation)
        if self.enable_greynoise:
            reputation = self._lookup_greynoise(reputation)
        if self.enable_crowdsec:
            reputation = self._lookup_crowdsec(reputation)
        if self.enable_whois:
            reputation = self._lookup_whois(reputation)
        return reputation

    def _lookup_abuseipdb(self, reputation: ReputationInfo) -> ReputationInfo:
        if not self.abuseipdb_key:
            return reputation
        query = urlencode({"ipAddress": reputation.ip, "maxAgeInDays": "90", "verbose": ""})
        request = Request(
            f"https://api.abuseipdb.com/api/v2/check?{query}",
            headers={"Key": self.abuseipdb_key, "Accept": "application/json"},
        )
        payload = self._read_json(request)
        data = payload.get("data", {}) if isinstance(payload, dict) else {}
        if not isinstance(data, dict):
            return reputation
        return replace(
            reputation,
            country=str(data.get("countryCode") or reputation.country),
            organization=str(data.get("isp") or data.get("domain") or reputation.organization),
            abuse_score=_optional_int(data.get("abuseConfidenceScore")),
        )

    def _lookup_greynoise(self, reputation: ReputationInfo) -> ReputationInfo:
        headers = {"Accept": "application/json"}
        if self.greynoise_key:
            headers["key"] = self.greynoise_key
        request = Request(f"https://api.greynoise.io/v3/community/{reputation.ip}", headers=headers)
        payload = self._read_json(request)
        if not isinstance(payload, dict):
            return reputation
        return replace(
            reputation,
            greynoise_classification=str(payload.get("classification") or "").lower(),
            greynoise_noise=bool(payload.get("noise")),
            greynoise_riot=bool(payload.get("riot")),
        )

    def _lookup_crowdsec(self, reputation: ReputationInfo) -> ReputationInfo:
        cscli = shutil.which("cscli")
        if not cscli:
            return reputation
        try:
            completed = subprocess.run(
                [cscli, "decisions", "list", "-i", reputation.ip, "-o", "json"],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return reputation
        if completed.returncode != 0 or not completed.stdout.strip():
            return reputation
        try:
            payload = json.loads(completed.stdout)
        except json.JSONDecodeError:
            return reputation
        return replace(reputation, crowdsec_listed=bool(payload))

    def _lookup_whois(self, reputation: ReputationInfo) -> ReputationInfo:
        whois = shutil.which("whois")
        if not whois:
            return reputation
        try:
            completed = subprocess.run(
                [whois, reputation.ip],
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except (OSError, subprocess.SubprocessError):
            return reputation
        if completed.returncode != 0:
            return reputation
        parsed = _parse_whois(completed.stdout)
        return replace(
            reputation,
            country=parsed.get("country", reputation.country),
            asn=parsed.get("asn", reputation.asn),
            organization=parsed.get("organization", reputation.organization),
        )

    def _read_json(self, request: Request) -> Any:
        try:
            with urlopen(request, timeout=self.timeout_seconds) as response:
                return json.loads(response.read().decode("utf-8"))
        except (HTTPError, URLError, TimeoutError, OSError, json.JSONDecodeError):
            return {}


def load_assessor(
    whitelist_path: Path | None,
    blacklist_path: Path | None,
    abuseipdb_key: str | None,
    greynoise_key: str | None,
) -> CriticalityAssessor:
    return CriticalityAssessor(
        whitelist=MatchRules.from_file(whitelist_path),
        blacklist=MatchRules.from_file(blacklist_path),
        abuseipdb_key=abuseipdb_key if abuseipdb_key is not None else os.getenv("ABUSEIPDB_KEY", DEFAULT_ABUSEIPDB_KEY),
        greynoise_key=greynoise_key if greynoise_key is not None else os.getenv("GREYNOISE_KEY", ""),
    )


def _parse_networks(values: object) -> tuple[ipaddress._BaseNetwork, ...]:
    networks = []
    for value in _as_list(values):
        networks.append(ipaddress.ip_network(str(value), strict=False))
    return tuple(networks)


def _as_list(values: object) -> list[object]:
    if values is None:
        return []
    if isinstance(values, (str, int)):
        return [values]
    if isinstance(values, list):
        return values
    if isinstance(values, tuple):
        return list(values)
    return [values]


def _parse_whois(output: str) -> dict[str, str]:
    result: dict[str, str] = {}
    for line in output.splitlines():
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        normalized_key = key.strip().lower()
        value = value.strip()
        if not value:
            continue
        if normalized_key == "country" and "country" not in result:
            result["country"] = value.upper()
        elif normalized_key in {"origin", "originas", "aut-num"} and "asn" not in result:
            result["asn"] = _normalize_asn(value)
        elif normalized_key in {"orgname", "org-name", "organization", "netname"} and "organization" not in result:
            result["organization"] = value
    return result


def _normalize_country(value: object) -> str:
    return str(value).strip().upper()


def _normalize_asn(value: object) -> str:
    match = re.search(r"(\d+)", str(value))
    return f"AS{match.group(1)}" if match else str(value).strip().upper()


def _optional_int(value: object) -> int | None:
    if value is None:
        return None
    try:
        return int(value) # type: ignore
    except (TypeError, ValueError):
        return None
