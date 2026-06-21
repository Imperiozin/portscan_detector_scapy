from __future__ import annotations

import json
import sqlite3
from pathlib import Path

from .detector import PortScanEvent


class SQLiteEventStore:
    def __init__(self, database_path: Path) -> None:
        self.database_path = database_path
        self._initialize()

    def save(self, event: PortScanEvent) -> None:
        with sqlite3.connect(self.database_path) as connection:
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
                    port_count,
                    packet_count
                ) values (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    event.detected_at.isoformat(),
                    event.first_seen.isoformat(),
                    event.last_seen.isoformat(),
                    event.source_ip,
                    event.target_ip,
                    json.dumps(event.ports),
                    json.dumps(event.scan_types),
                    event.port_count,
                    event.packet_count,
                ),
            )

    def _initialize(self) -> None:
        with sqlite3.connect(self.database_path) as connection:
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
                    port_count integer not null,
                    packet_count integer not null
                )
                """
            )
            columns = {
                row[1]
                for row in connection.execute("pragma table_info(port_scan_events)")
            }
            if "scan_types" not in columns:
                connection.execute(
                    """
                    alter table port_scan_events
                    add column scan_types text not null default '[]'
                    """
                )
            connection.execute(
                """
                create index if not exists idx_port_scan_events_source_target
                on port_scan_events (source_ip, target_ip, detected_at)
                """
            )
