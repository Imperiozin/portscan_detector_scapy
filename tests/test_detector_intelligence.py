from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from scapy.layers.inet import ICMP, IP, TCP, UDP

from portscan_detector.demo_scenario import run_demo_scenario
from portscan_detector.detector import HORIZONTAL_SCAN, SYN_SCAN, PortScanDetector
from portscan_detector.reputation import CriticalityAssessor
from portscan_detector.storage import SQLiteEventStore
from portscan_detector.web_dashboard import _dashboard_payload


class DetectorIntelligenceTest(unittest.TestCase):
    def test_syn_scan_infers_open_services_and_remote_access_hypothesis(self) -> None:
        events = []
        detector = PortScanDetector(
            threshold=3,
            window_seconds=20,
            cooldown_seconds=60,
            on_event=events.append,
            print_events=False,
        )

        source = "192.168.1.50"
        target = "10.0.0.8"
        base_time = 1000.0
        for index, port in enumerate((22, 80, 3389)):
            packet = IP(src=source, dst=target) / TCP(sport=40000 + index, dport=port, flags="S")
            packet.time = base_time + index
            detector.process_packet(packet)

            response = IP(src=target, dst=source) / TCP(sport=port, dport=40000 + index, flags="SA")
            response.time = base_time + index + 0.1
            detector.process_packet(response)

        self.assertTrue(events)
        event = events[-1]
        open_ports = {service.port for service in event.open_services}

        self.assertIn(SYN_SCAN, event.scan_types)
        self.assertIn(22, open_ports)
        self.assertIn(80, open_ports)
        self.assertIn("Reconhecimento de acesso remoto", event.hypothesis)
        self.assertGreaterEqual(event.risk_score, 70)
        self.assertGreaterEqual(event.confidence, 0.7)

    def test_horizontal_windows_service_scan_is_classified_as_campaign(self) -> None:
        events = []
        detector = PortScanDetector(
            threshold=3,
            window_seconds=20,
            cooldown_seconds=60,
            on_event=events.append,
            print_events=False,
        )

        source = "192.168.1.60"
        base_time = 2000.0
        for index, target in enumerate(("10.0.0.10", "10.0.0.11", "10.0.0.12")):
            packet = IP(src=source, dst=target) / TCP(sport=41000 + index, dport=445, flags="S")
            packet.time = base_time + index
            detector.process_packet(packet)

        self.assertTrue(events)
        event = events[-1]

        self.assertIn(HORIZONTAL_SCAN, event.scan_types)
        self.assertEqual(event.target_ip, "*")
        self.assertEqual(event.targets, ("10.0.0.10", "10.0.0.11", "10.0.0.12"))
        self.assertIn("Windows", event.hypothesis)
        self.assertTrue(event.campaign_id.startswith("ID-"))

    def test_storage_persists_operational_fields_for_ui(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store = SQLiteEventStore(database)
            events = []
            detector = PortScanDetector(
                threshold=2,
                window_seconds=20,
                cooldown_seconds=60,
                on_event=lambda event: (events.append(event), store.save(event)),
                print_events=False,
            )

            for index, port in enumerate((22, 3389)):
                packet = IP(src="192.168.1.70", dst="10.0.0.20") / TCP(
                    sport=42000 + index,
                    dport=port,
                    flags="S",
                )
                packet.time = 3000.0 + index
                detector.process_packet(packet)

            recent = store.fetch_recent_events(limit=5)
            campaigns = store.fetch_campaigns(limit=5)
            overview = store.fetch_overview()
            highest_risk = store.fetch_highest_risk_event()

            self.assertEqual(len(recent), 1)
            self.assertEqual(len(campaigns), 1)
            self.assertEqual(overview["total_events"], 1)
            self.assertIsNotNone(highest_risk)
            self.assertEqual(recent[0]["severity"], events[0].severity)
            self.assertEqual(recent[0]["campaign_id"], events[0].campaign_id)

    def test_exposure_is_preserved_per_campaign(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "events.db"
            store = SQLiteEventStore(database)
            detector = PortScanDetector(
                threshold=2,
                window_seconds=20,
                cooldown_seconds=60,
                on_event=store.save,
                print_events=False,
            )

            for source_index, source in enumerate(("192.168.1.80", "192.168.1.81")):
                for port_index, port in enumerate((22, 3389)):
                    packet = IP(src=source, dst="10.0.0.30") / TCP(
                        sport=43000 + source_index * 10 + port_index,
                        dport=port,
                        flags="S",
                    )
                    packet.time = 5000.0 + source_index * 30 + port_index
                    detector.process_packet(packet)

            exposure = store.fetch_exposure(limit=20)
            ssh_exposure = [
                item
                for item in exposure
                if item["target_ip"] == "10.0.0.30" and item["port"] == 22
            ]
            campaign_ids = {item["campaign_id"] for item in ssh_exposure}

            self.assertEqual(len(ssh_exposure), 2)
            self.assertEqual(len(campaign_ids), 2)

    def test_udp_icmp_unreachable_marks_service_closed(self) -> None:
        events = []
        detector = PortScanDetector(
            threshold=2,
            window_seconds=20,
            cooldown_seconds=60,
            on_event=events.append,
            print_events=False,
        )

        for index, port in enumerate((161, 47808)):
            probe = IP(src="172.16.1.77", dst="10.10.60.5") / UDP(
                sport=47000 + index,
                dport=port,
            )
            probe.time = 4000.0 + index
            detector.process_packet(probe)

            response = (
                IP(src="10.10.60.5", dst="172.16.1.77")
                / ICMP(type=3, code=3)
                / IP(src="172.16.1.77", dst="10.10.60.5")
                / UDP(sport=47000 + index, dport=port)
            )
            response.time = 4000.1 + index
            detector.process_packet(response)

        self.assertTrue(events)
        closed_ports = {
            service.port
            for service in events[-1].services
            if service.exposure == "closed"
        }
        self.assertIn(161, closed_ports)

    def test_technical_risk_feeds_operational_criticality(self) -> None:
        events = []
        assessor = CriticalityAssessor(
            abuseipdb_key="",
            enable_whois=False,
            enable_crowdsec=False,
            enable_greynoise=False,
        )
        detector = PortScanDetector(
            threshold=3,
            window_seconds=20,
            cooldown_seconds=60,
            on_event=events.append,
            assess_event=assessor.assess,
            print_events=False,
        )

        source = "192.168.1.90"
        target = "10.0.0.40"
        base_time = 4500.0
        for index, port in enumerate((22, 3389, 5985)):
            packet = IP(src=source, dst=target) / TCP(
                sport=48000 + index,
                dport=port,
                flags="S",
            )
            packet.time = base_time + index
            detector.process_packet(packet)

        self.assertTrue(events)
        event = events[-1]
        self.assertGreater(event.risk_score, 0)
        self.assertGreaterEqual(event.criticality, event.risk_score)
        self.assertTrue(any("risco_tecnico" in item for item in event.criticality_reasons))

    def test_demo_scenario_populates_campaigns_for_ui(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            database = Path(directory) / "demo.db"
            store = SQLiteEventStore(database)
            assessor = CriticalityAssessor(
                abuseipdb_key="",
                enable_whois=False,
                enable_crowdsec=False,
                enable_greynoise=False,
            )
            detector = PortScanDetector(
                threshold=4,
                window_seconds=20,
                cooldown_seconds=60,
                on_event=store.save,
                assess_event=assessor.assess,
                print_events=False,
            )

            packet_count = run_demo_scenario(detector)
            overview = store.fetch_overview()
            campaigns = store.fetch_campaigns(limit=10)
            exposure = store.fetch_exposure(limit=20)

            self.assertGreater(packet_count, 20)
            self.assertGreaterEqual(overview["total_events"], 4)
            self.assertGreaterEqual(overview["campaigns"], 4)
            self.assertTrue(any(item["exposure"] == "open" for item in exposure))
            self.assertTrue(any("acesso remoto" in " ".join(item["hypotheses"]) for item in campaigns))

            payload = _dashboard_payload(store)
            self.assertIn("overview", payload)
            self.assertIn("events", payload)
            self.assertIn("campaigns", payload)
            self.assertIn("exposure", payload)
            self.assertIn("briefing", payload)
            self.assertIsNotNone(payload["highestRisk"])
            self.assertIn("triage", payload["campaigns"][0])
            self.assertIn("case_id", payload["campaigns"][0])
            self.assertTrue(payload["campaigns"][0]["case_id"].startswith("ID-"))
            self.assertTrue(payload["campaigns"][0]["campaign_id"].startswith("ID-"))
            self.assertIn("criticality", payload["campaigns"][0])
            self.assertIn("criticality_reasons", payload["campaigns"][0])
            self.assertGreater(payload["campaigns"][0]["criticality"], 0)
            self.assertIn("decision", payload["campaigns"][0]["triage"])
            self.assertIn("attempted", payload["campaigns"][0]["triage"])
            self.assertIn("attack_label", payload["campaigns"][0]["triage"])
            self.assertIn("confirmation_level", payload["campaigns"][0]["triage"])
            self.assertIn("learned", payload["campaigns"][0]["triage"])
            self.assertIn("limitation", payload["campaigns"][0]["triage"])
            self.assertIn("targeted_services", payload["campaigns"][0]["triage"])
            self.assertIn("phase", payload["campaigns"][0]["triage"])
            self.assertIn("severity_reason", payload["campaigns"][0]["triage"])
            self.assertIn("missing_confirmation", payload["campaigns"][0]["triage"])
            self.assertIn("next_query", payload["campaigns"][0]["triage"])
            self.assertIn("investigation_checklist", payload["campaigns"][0]["triage"])
            self.assertIn("service_roles", payload["campaigns"][0]["triage"])
            self.assertIn("case_type", payload["campaigns"][0]["triage"])
            self.assertIn("operator_focus", payload["campaigns"][0]["triage"])
            self.assertIn("attacker_objective", payload["campaigns"][0]["triage"])
            self.assertIn("attacker_next_step", payload["campaigns"][0]["triage"])
            self.assertIn("defensive_value", payload["campaigns"][0]["triage"])
            self.assertIn("business_impact", payload["campaigns"][0]["triage"])
            self.assertIn("criticality_context", payload["campaigns"][0]["triage"])
            self.assertIn("pivot_queries", payload["campaigns"][0]["triage"])
            self.assertTrue(payload["campaigns"][0]["triage"]["pivot_queries"])

            case_types = {
                item["triage"]["case_type"]
                for item in payload["campaigns"]
            }
            self.assertIn("remote_access_validation", case_types)
            self.assertIn("redis_horizontal_sweep", case_types)
            self.assertIn("kubernetes_api_distributed", case_types)
            self.assertIn("slow_platform_inventory", case_types)
            self.assertIn("udp_ot_probe", case_types)
            json.dumps(payload)


if __name__ == "__main__":
    unittest.main()
