from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path
from typing import Any, Iterable

from .detector import PortScanEvent


SEVERITY_WEIGHT = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
}


class SQLiteEventStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._initialize()

    def save(self, event: PortScanEvent) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    insert into port_scan_events (
                        detected_at,
                        first_seen,
                        last_seen,
                        source_ip,
                        target_ip,
                        ports,
                        scan_types,
                        criticality,
                        criticality_reasons,
                        port_count,
                        packet_count,
                        protocol,
                        sources,
                        targets,
                        services,
                        service_categories,
                        hypothesis,
                        intent,
                        severity,
                        confidence,
                        risk_score,
                        mitre_technique,
                        evidence,
                        recommendations,
                        campaign_id,
                        duration_seconds,
                        packets_per_second
                    ) values (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        event.detected_at.isoformat(),
                        event.first_seen.isoformat(),
                        event.last_seen.isoformat(),
                        event.source_ip,
                        event.target_ip,
                        _json_dumps(event.ports),
                        _json_dumps(event.scan_types),
                        event.criticality,
                        _json_dumps(event.criticality_reasons),
                        event.port_count,
                        event.packet_count,
                        event.protocol,
                        _json_dumps(event.sources),
                        _json_dumps(event.targets),
                        _json_dumps(service.to_dict() for service in event.services),
                        _json_dumps(event.service_categories),
                        event.hypothesis,
                        event.intent,
                        event.severity,
                        event.confidence,
                        event.risk_score,
                        event.mitre_technique,
                        _json_dumps(event.evidence),
                        _json_dumps(event.recommendations),
                        event.campaign_id,
                        event.duration_seconds,
                        event.packets_per_second,
                    ),
                )

    def fetch_recent_events(self, limit: int = 50) -> list[dict[str, Any]]:
        with closing(self._connect()) as connection:
            rows = connection.execute(
                """
                select *
                from port_scan_events
                order by detected_at desc, id desc
                limit ?
                """,
                (limit,),
            ).fetchall()
        return [_row_to_event(row) for row in rows]

    def fetch_highest_risk_event(self) -> dict[str, Any] | None:
        with closing(self._connect()) as connection:
            row = connection.execute(
                """
                select *
                from port_scan_events
                order by max(risk_score, criticality) desc, detected_at desc, id desc
                limit 1
                """
            ).fetchone()
        if row is None:
            return None
        return _row_to_event(row)

    def fetch_campaigns(self, limit: int = 25) -> list[dict[str, Any]]:
        events = self.fetch_recent_events(limit=1000)
        campaigns: dict[str, dict[str, Any]] = {}

        for event in events:
            campaign_id = str(event.get("campaign_id") or "sem-campanha")
            campaign = campaigns.setdefault(
                campaign_id,
                {
                    "campaign_id": campaign_id,
                    "first_seen": event["first_seen"],
                    "last_seen": event["last_seen"],
                    "sources": set(),
                    "targets": set(),
                    "ports": set(),
                    "hypotheses": set(),
                    "severities": set(),
                    "risk_score": 0,
                    "event_count": 0,
                },
            )
            event_score = max(int(event.get("risk_score") or 0), int(event.get("criticality") or 0))
            campaign["first_seen"] = min(campaign["first_seen"], event["first_seen"])
            campaign["last_seen"] = max(campaign["last_seen"], event["last_seen"])
            campaign["sources"].update(event.get("sources") or [event.get("source_ip")])
            campaign["targets"].update(event.get("targets") or [event.get("target_ip")])
            campaign["ports"].update(event.get("ports") or [])
            campaign["hypotheses"].add(event.get("hypothesis", ""))
            campaign["severities"].add(event.get("severity", "low"))
            campaign["risk_score"] = max(campaign["risk_score"], event_score)
            campaign["event_count"] += 1

        normalized = []
        for campaign in campaigns.values():
            severities = sorted(
                campaign["severities"],
                key=lambda item: -SEVERITY_WEIGHT.get(str(item), 0),
            )
            normalized.append(
                {
                    "campaign_id": campaign["campaign_id"],
                    "first_seen": campaign["first_seen"],
                    "last_seen": campaign["last_seen"],
                    "sources": sorted(item for item in campaign["sources"] if item),
                    "targets": sorted(item for item in campaign["targets"] if item),
                    "ports": sorted(campaign["ports"]),
                    "hypotheses": sorted(item for item in campaign["hypotheses"] if item),
                    "risk_score": campaign["risk_score"],
                    "event_count": campaign["event_count"],
                    "severity": severities[0] if severities else "low",
                }
            )

        return sorted(
            normalized,
            key=lambda item: (
                int(item["risk_score"]),
                SEVERITY_WEIGHT.get(str(item["severity"]), 0),
                str(item["last_seen"]),
            ),
            reverse=True,
        )[:limit]

    def fetch_exposure(self, limit: int = 50) -> list[dict[str, Any]]:
        events = self.fetch_recent_events(limit=1000)
        exposures: dict[tuple[str, str, int, str], dict[str, Any]] = {}

        for event in events:
            targets = event.get("targets") or [event.get("target_ip", "*")]
            services = event.get("services") or []
            campaign_id = str(event.get("campaign_id") or "")
            for target in targets:
                for service in services:
                    key = (
                        campaign_id,
                        str(target),
                        int(service.get("port", 0)),
                        str(service.get("protocol", "unknown")),
                    )
                    current = exposures.get(key)
                    exposure = str(service.get("exposure", "unknown"))
                    candidate = {
                        "target_ip": str(target),
                        "port": int(service.get("port", 0)),
                        "protocol": str(service.get("protocol", "unknown")),
                        "service": str(service.get("service", "serviço não catalogado")),
                        "category": str(service.get("category", "generic")),
                        "exposure": exposure,
                        "risk": int(service.get("risk", 0)),
                        "last_seen": event.get("last_seen"),
                        "source_ip": event.get("source_ip"),
                        "campaign_id": campaign_id,
                    }
                    if current is None or _exposure_priority(exposure) > _exposure_priority(str(current["exposure"])):
                        exposures[key] = candidate

        return sorted(
            exposures.values(),
            key=lambda item: (-int(item["risk"]), str(item["target_ip"]), int(item["port"])),
        )[:limit]

    def fetch_overview(self) -> dict[str, Any]:
        events = self.fetch_recent_events(limit=1000)
        campaigns = self.fetch_campaigns(limit=1000)
        exposures = self.fetch_exposure(limit=1000)
        high_or_critical = sum(1 for event in events if event.get("severity") in {"high", "critical"})
        open_services = sum(1 for item in exposures if item.get("exposure") == "open")
        return {
            "total_events": len(events),
            "high_or_critical": high_or_critical,
            "campaigns": len(campaigns),
            "open_services": open_services,
            "max_risk_score": max(
                (
                    max(int(event.get("risk_score") or 0), int(event.get("criticality") or 0))
                    for event in events
                ),
                default=0,
            ),
        }

    def _initialize(self) -> None:
        with closing(self._connect()) as connection:
            with connection:
                connection.execute(
                    """
                    create table if not exists port_scan_events (
                        id integer primary key autoincrement,
                        detected_at text not null,
                        first_seen text not null,
                        last_seen text not null,
                        source_ip text not null,
                        target_ip text not null,
                        ports text not null,
                        scan_types text not null default '[]',
                        criticality integer not null default 0,
                        criticality_reasons text not null default '[]',
                        port_count integer not null,
                        packet_count integer not null
                    )
                    """
                )
                self._ensure_columns(connection)
                connection.execute(
                    """
                    create index if not exists idx_port_scan_events_source_target
                    on port_scan_events (source_ip, target_ip, detected_at)
                    """
                )
                connection.execute(
                    """
                    create index if not exists idx_port_scan_events_campaign
                    on port_scan_events (campaign_id, detected_at)
                    """
                )
                connection.execute(
                    """
                    create index if not exists idx_port_scan_events_severity
                    on port_scan_events (severity, risk_score)
                    """
                )

    def _ensure_columns(self, connection: sqlite3.Connection) -> None:
        columns = {
            row[1]
            for row in connection.execute("pragma table_info(port_scan_events)")
        }
        definitions = {
            "scan_types": "text not null default '[]'",
            "criticality": "integer not null default 0",
            "criticality_reasons": "text not null default '[]'",
            "protocol": "text not null default 'unknown'",
            "sources": "text not null default '[]'",
            "targets": "text not null default '[]'",
            "services": "text not null default '[]'",
            "service_categories": "text not null default '[]'",
            "hypothesis": "text not null default 'Reconhecimento de superfície de rede'",
            "intent": "text not null default ''",
            "severity": "text not null default 'low'",
            "confidence": "real not null default 0",
            "risk_score": "integer not null default 0",
            "mitre_technique": "text not null default ''",
            "evidence": "text not null default '[]'",
            "recommendations": "text not null default '[]'",
            "campaign_id": "text not null default ''",
            "duration_seconds": "real not null default 0",
            "packets_per_second": "real not null default 0",
        }
        for column, definition in definitions.items():
            if column not in columns:
                connection.execute(
                    f"alter table port_scan_events add column {column} {definition}"
                )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.database_path)
        connection.row_factory = sqlite3.Row
        return connection


def _json_dumps(value: Iterable[Any]) -> str:
    return json.dumps(list(value), ensure_ascii=True)


def _json_loads(value: Any, default: Any) -> Any:
    if value in (None, ""):
        return default
    try:
        return json.loads(str(value))
    except json.JSONDecodeError:
        return default


def _row_to_event(row: sqlite3.Row) -> dict[str, Any]:
    item = dict(row)
    for key in (
        "ports",
        "scan_types",
        "criticality_reasons",
        "sources",
        "targets",
        "services",
        "service_categories",
        "evidence",
        "recommendations",
    ):
        item[key] = _json_loads(item.get(key), [])
    return item


def _exposure_priority(exposure: str) -> int:
    return {
        "open": 4,
        "filtered_or_inconclusive": 3,
        "attempted": 2,
        "unknown": 1,
        "closed": 0,
    }.get(exposure, 1)
