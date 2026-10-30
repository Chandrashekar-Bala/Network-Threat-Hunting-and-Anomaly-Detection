from __future__ import annotations

import struct
import json
import unittest
from datetime import datetime, timedelta, timezone
from html.parser import HTMLParser
from io import StringIO
from pathlib import Path
from unittest.mock import patch

from nth_signal.detection import analyze
from nth_signal.ingestion import read_flows
from nth_signal.mitre import mappings_for
from nth_signal.pcap import read_pcap
from nth_signal.config import DetectionConfig
from nth_signal.intel import load_iocs, match_flow
from nth_signal.pcap import _dns_query
from nth_signal.report import render_html, report_payload


class ElementIds(HTMLParser):
    def __init__(self) -> None:
        super().__init__()
        self.ids: set[str] = set()

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            if name == "id" and value:
                self.ids.add(value)


def ipv4_udp(src: str, dst: str, sport: int, dport: int, payload: bytes = b"") -> bytes:
    src_bytes = bytes(int(part) for part in src.split("."))
    dst_bytes = bytes(int(part) for part in dst.split("."))
    udp_len = 8 + len(payload)
    total = 20 + udp_len
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, total, 1, 0, 64, 17, 0, src_bytes, dst_bytes)
    udp = struct.pack("!HHHH", sport, dport, udp_len, 0)
    ethernet = b"\x00" * 12 + b"\x08\x00"
    return ethernet + ip + udp + payload


def pcap_record(timestamp: int, packet: bytes) -> bytes:
    return struct.pack("<IIII", timestamp, 0, len(packet), len(packet)) + packet


def pcapng_block(block_type: int, body: bytes) -> bytes:
    body += b"\x00" * ((-len(body)) % 4)
    size = 12 + len(body)
    return struct.pack("<II", block_type, size) + body + struct.pack("<I", size)


def dns_query(name: str) -> bytes:
    labels = b"".join(bytes([len(label)]) + label.encode("ascii") for label in name.split(".")) + b"\x00"
    return struct.pack("!HHHHHH", 7, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def demo_flow(index: int, timestamp: datetime, dst_port: int = 443) -> dict:
    return {"id": index, "timestamp": timestamp, "src_ip": "10.0.0.5", "dst_ip": "8.8.8.8",
            "src_port": 50000 + index, "dst_port": dst_port, "protocol": "TCP", "service": "",
            "duration": 1.0, "src_bytes": 1200.0, "dst_bytes": 900.0, "src_packets": 2.0,
            "dst_packets": 2.0, "conn_state": "SF", "signals": [], "score": 0}


class IngestionTests(unittest.TestCase):
    def test_csv_headers_with_spaces_are_normalized(self) -> None:
        path = Path("flows.csv")
        content = "Source IP,Destination IP,Source Port,Destination Port,Protocol\n10.0.0.1,8.8.8.8,1234,443,TCP\n"
        with patch.object(Path, "open", return_value=StringIO(content)):
            flows, source_format = read_flows(path)
        self.assertEqual(source_format, "Delimited flow export")
        self.assertEqual((flows[0]["src_ip"], flows[0]["dst_ip"], flows[0]["dst_port"]), ("10.0.0.1", "8.8.8.8", 443))

    def test_tsv_input_is_normalized(self) -> None:
        content = "src_ip\tdst_ip\tsrc_port\tdst_port\tproto\n10.0.0.2\t192.0.2.8\t51000\t443\ttcp\n"
        with patch.object(Path, "open", return_value=StringIO(content)):
            flows, source_format = read_flows(Path("flows.tsv"))
        self.assertEqual(source_format, "Delimited flow export")
        self.assertEqual((flows[0]["src_ip"], flows[0]["dst_port"], flows[0]["protocol"]), ("10.0.0.2", 443, "TCP"))

    def test_zeek_dns_log_fields_are_normalized(self) -> None:
        content = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\tquery\n"
            "#types\ttime\taddr\taddr\tport\tport\tproto\tstring\n"
            "1735689600\t10.0.0.1\t8.8.8.8\t53000\t53\tudp\tcdn.example.test\n"
        )
        path = Path("dns.log")
        with patch.object(Path, "open", side_effect=lambda *args, **kwargs: StringIO(content)):
            flows, source_format = read_flows(path)
        self.assertEqual(source_format, "Zeek log")
        self.assertEqual(flows[0]["dns_query"], "cdn.example.test")

    def test_zeek_connection_log_is_normalized(self) -> None:
        content = (
            "#separator \\x09\n"
            "#fields\tts\tid.orig_h\tid.resp_h\tid.orig_p\tid.resp_p\tproto\tduration\torig_bytes\tresp_bytes\tconn_state\n"
            "#types\ttime\taddr\taddr\tport\tport\tproto\tinterval\tcount\tcount\tstring\n"
            "1735689600\t10.0.0.1\t192.0.2.8\t53000\t443\ttcp\t2.5\t500\t1200\tSF\n"
        )
        with patch.object(Path, "open", side_effect=lambda *args, **kwargs: StringIO(content)):
            flows, source_format = read_flows(Path("conn.log"))
        self.assertEqual(source_format, "Zeek log")
        self.assertEqual((flows[0]["src_bytes"], flows[0]["dst_bytes"], flows[0]["conn_state"]), (500.0, 1200.0, "SF"))

    def test_invalid_ip_rows_are_skipped(self) -> None:
        content = "src_ip,dst_ip,dst_port\nnot-an-ip,8.8.8.8,53\n10.0.0.1,8.8.8.8,53\n"
        with patch.object(Path, "open", return_value=StringIO(content)):
            flows, _ = read_flows(Path("flows.csv"))
        self.assertEqual(len(flows), 1)

    def test_classic_pcap_aggregates_bidirectional_packets(self) -> None:
        outbound = ipv4_udp("10.0.0.4", "8.8.8.8", 53000, 53, b"query")
        inbound = ipv4_udp("8.8.8.8", "10.0.0.4", 53, 53000, b"response")
        capture = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        capture += pcap_record(100, outbound) + pcap_record(101, inbound)
        path = Path("capture.pcap")
        with patch.object(Path, "read_bytes", return_value=capture):
            flows = read_pcap(path)
        self.assertEqual(len(flows), 1)
        self.assertEqual((flows[0]["src_ip"], flows[0]["dst_ip"], flows[0]["dst_port"]), ("10.0.0.4", "8.8.8.8", 53))
        self.assertEqual((flows[0]["src_packets"], flows[0]["dst_packets"]), (1, 1))
        self.assertEqual(flows[0]["duration"], 1)

    def test_pcapng_enhanced_packet_block(self) -> None:
        packet = ipv4_udp("192.0.2.10", "198.51.100.8", 60000, 53)
        section = pcapng_block(0x0A0D0D0A, struct.pack("<IHHq", 0x1A2B3C4D, 1, 0, -1))
        interface = pcapng_block(1, struct.pack("<HHI", 1, 0, 65535) + b"\x00" * 4)
        enhanced = pcapng_block(6, struct.pack("<IIIII", 0, 0, 1_000_000, len(packet), len(packet)) + packet)
        path = Path("capture.pcapng")
        with patch.object(Path, "read_bytes", return_value=section + interface + enhanced):
            flows = read_pcap(path)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]["protocol"], "UDP")
        self.assertEqual(flows[0]["dst_port"], 53)

    def test_pcap_extracts_dns_query_name(self) -> None:
        packet = ipv4_udp("10.0.0.4", "8.8.8.8", 53000, 53, dns_query("cdn.example.test"))
        capture = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        capture += pcap_record(100, packet)
        with patch.object(Path, "read_bytes", return_value=capture):
            flows = read_pcap(Path("dns.pcap"))
        self.assertEqual(flows[0]["dns_queries"], ["cdn.example.test"])

    def test_truncated_dns_question_is_ignored(self) -> None:
        self.assertIsNone(_dns_query(dns_query("cdn.example.test")[:-2]))

    def test_packet_with_transport_header_outside_ip_length_is_ignored(self) -> None:
        packet = bytearray(ipv4_udp("10.0.0.4", "8.8.8.8", 53000, 53))
        struct.pack_into("!H", packet, 16, 24)  # IPv4 length ends before the UDP header.
        capture = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 1)
        capture += pcap_record(100, bytes(packet))
        with patch.object(Path, "read_bytes", return_value=capture):
            with self.assertRaisesRegex(ValueError, "No TCP or UDP"):
                read_pcap(Path("malformed.pcap"))

    def test_raw_ipv4_link_type_is_supported(self) -> None:
        ethernet_frame = ipv4_udp("10.0.0.4", "8.8.8.8", 53000, 53)
        raw_ip_packet = ethernet_frame[14:]
        capture = b"\xd4\xc3\xb2\xa1" + struct.pack("<HHIIII", 2, 4, 0, 0, 65535, 101)
        capture += pcap_record(100, raw_ip_packet)
        with patch.object(Path, "read_bytes", return_value=capture):
            flows = read_pcap(Path("raw-ip.pcap"))
        self.assertEqual((flows[0]["src_ip"], flows[0]["dst_port"]), ("10.0.0.4", 53))

    def test_truncated_pcap_is_reported_as_an_error(self) -> None:
        with patch.object(Path, "read_bytes", return_value=b"\xd4\xc3\xb2\xa1short"):
            with self.assertRaisesRegex(ValueError, "shorter than its global header"):
                read_pcap(Path("broken.pcap"))


class DetectionTests(unittest.TestCase):
    def test_vertical_scan_has_explainable_signal_and_attack_candidate(self) -> None:
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flows = [demo_flow(i, now + timedelta(seconds=i), 1000 + i) for i in range(1, 16)]
        analyzed = analyze(flows)
        self.assertTrue(all(any(s["title"] == "Vertical scan behavior" for s in f["signals"]) for f in analyzed))
        self.assertTrue(all(any(m["id"] == "T1046" for m in f["mitre"]) for f in analyzed))

    def test_severity_confidence_and_priority_are_separate(self) -> None:
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flows = [demo_flow(i, now + timedelta(seconds=i), 1000 + i) for i in range(1, 16)]
        finding = analyze(flows)[0]["finding"]
        self.assertEqual(finding["severity"], "High")
        self.assertEqual(finding["priority"], "Medium")
        self.assertEqual(finding["confidence"], "Medium")
        self.assertEqual(finding["rule_ids"], ["NTH-NET-SCAN-002"])
        self.assertEqual(finding["evidence"][0]["evidence_type"], "unique_ports")
        self.assertEqual(finding["evidence"][0]["entities"], ["10.0.0.5", "8.8.8.8"])

    def test_legacy_score_field_remains_a_priority_score_alias(self) -> None:
        flow = demo_flow(1, datetime(2025, 1, 1, tzinfo=timezone.utc), 4444)
        result = analyze([flow])[0]
        self.assertEqual(result["score"], result["priority_score"])
        self.assertIn(result["priority"], {"Informational", "Low", "Medium", "High", "Critical"})
        self.assertEqual(result["finding"]["priority_score"], result["score"])

    def test_scan_threshold_must_be_met_inside_its_time_window(self) -> None:
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flows = [demo_flow(i, start + timedelta(hours=i), 1000 + i) for i in range(1, 16)]
        analyzed = analyze(flows)
        self.assertTrue(all("Vertical scan behavior" not in {s["title"] for s in f["signals"]} for f in analyzed))

    def test_scan_without_timestamps_does_not_claim_a_time_window(self) -> None:
        flows = [demo_flow(i, None, 1000 + i) for i in range(1, 16)]
        analyzed = analyze(flows)
        detail = next(
            signal["detail"]
            for signal in analyzed[0]["signals"]
            if signal["title"] == "Vertical scan behavior"
        )
        self.assertIn("across the capture", detail)
        self.assertNotIn("within 60 seconds", detail)

    def test_repeated_failures_are_grouped_by_destination_and_time(self) -> None:
        start = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flows = [demo_flow(i, start + timedelta(seconds=i)) for i in range(10)]
        for flow in flows:
            flow["conn_state"] = "S0"
            flow["dst_port"] = 3389
        analyzed = analyze(flows)
        self.assertTrue(all(any(s["title"] == "Repeated connection failures" for s in f["signals"]) for f in analyzed))

    def test_regular_intervals_flag_beacon_candidate(self) -> None:
        now = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flows = [demo_flow(i, now + timedelta(seconds=30 * i)) for i in range(6)]
        analyzed = analyze(flows)
        self.assertTrue(all(any(s["title"] == "Regular beacon pattern" for s in f["signals"]) for f in analyzed))
        self.assertTrue(all(any(m["id"] == "T1071" for m in f["mitre"]) for f in analyzed))

    def test_unmapped_signal_does_not_get_forced_attack_mapping(self) -> None:
        self.assertEqual(mappings_for([{"title": "Outbound volume outlier"}]), [])

    def test_dns_entropy_and_domain_ioc_are_explainable(self) -> None:
        flow = demo_flow(1, datetime(2025, 1, 1, tzinfo=timezone.utc))
        flow["dns_queries"] = ["q7m4x9v2a8k3n5p6z1r0.example.test"]
        iocs = {"example.test": {"indicator": "example.test", "type": "domain", "source": "test feed", "confidence": "high", "notes": "fixture"}}
        result = analyze([flow], iocs=iocs)[0]
        titles = {signal["title"] for signal in result["signals"]}
        self.assertIn("High entropy DNS label", titles)
        self.assertIn("Local threat feed match", titles)
        self.assertEqual(result["ioc_matches"][0]["source"], "test feed")

    def test_ioc_confidence_changes_priority_without_creating_critical_alert(self) -> None:
        now = datetime.now(timezone.utc)
        low = {"8.8.8.8": {"indicator": "8.8.8.8", "type": "ip", "source": "one feed", "confidence": "low", "notes": ""}}
        high = {"8.8.8.8": {"indicator": "8.8.8.8", "type": "ip", "source": "one feed", "confidence": "high", "notes": ""}}
        low_result = analyze([demo_flow(1, now)], iocs=low)[0]
        high_result = analyze([demo_flow(1, now)], iocs=high)[0]
        self.assertGreater(high_result["priority_score"], low_result["priority_score"])
        self.assertEqual(high_result["severity"], "Medium")
        self.assertNotEqual(high_result["priority"], "Critical")
        self.assertEqual(high_result["finding"]["evidence"][0]["attributes"]["priority_points"], high_result["priority_score"])

    def test_expired_ioc_is_marked_stale_and_reduced(self) -> None:
        flow = demo_flow(1, datetime.now(timezone.utc))
        indicator = {"8.8.8.8": {"indicator": "8.8.8.8", "type": "ip", "source": "feed", "confidence": "high", "notes": "", "expires_at": "2000-01-01T00:00:00+00:00"}}
        result = analyze([flow], iocs=indicator)[0]
        self.assertEqual(result["ioc_matches"][0]["freshness"], "Expired")
        self.assertEqual(result["ioc_matches"][0]["assessed_confidence"], "Low")
        self.assertLessEqual(result["priority_score"], 7)

    def test_domain_match_includes_subdomains(self) -> None:
        iocs = {"example.test": {"indicator": "example.test", "type": "domain", "source": "feed", "confidence": "high", "notes": ""}}
        flow = {"src_ip": "10.0.0.1", "dst_ip": "8.8.8.8", "dns_queries": ["a.b.example.test"]}
        self.assertEqual(match_flow(flow, iocs)[0]["indicator"], "example.test")

    def test_configuration_rejects_unknown_keys_and_bad_thresholds(self) -> None:
        with patch.object(Path, "read_text", return_value=json.dumps({"scan_unique_threshold": 0})):
            with self.assertRaisesRegex(ValueError, "greater than zero"):
                DetectionConfig.from_file(Path("config.json"))
        with patch.object(Path, "read_text", return_value=json.dumps({"made_up_rule": True})):
            with self.assertRaisesRegex(ValueError, "Unknown configuration"):
                DetectionConfig.from_file(Path("config.json"))
        with self.assertRaisesRegex(ValueError, "between 0 and 1"):
            DetectionConfig(ioc_confidence_factors={"high": 1.5}).validate()
        with self.assertRaisesRegex(ValueError, "below the critical"):
            DetectionConfig(ioc_score_cap=80).validate()

    def test_configuration_can_add_ports_and_disable_rules(self) -> None:
        timestamp = datetime(2025, 1, 1, tzinfo=timezone.utc)
        flow = demo_flow(1, timestamp, 8444)
        config = DetectionConfig(
            high_risk_ports={"8444": "internal test service"},
            disabled_rules=["High risk destination port"],
        )
        result = analyze([flow], config=config)[0]
        self.assertFalse(any(signal["title"] == "High risk destination port" for signal in result["signals"]))

        enabled = analyze([demo_flow(2, timestamp, 8444)], config=DetectionConfig(
            high_risk_ports={"8444": "internal test service"}
        ))[0]
        reason = next(signal for signal in enabled["signals"] if signal["title"] == "High risk destination port")
        self.assertIn("internal test service", reason["detail"])

    def test_ioc_csv_keeps_source_and_rejects_bad_type(self) -> None:
        feed = (
            "indicator,type,source,confidence,notes,last_seen\n"
            "203.0.113.10,ipv4,team feed,high,example,2025-01-01T00:00:00Z\n"
            "203.0.113.10,ipv4,partner feed,medium,second report,2025-01-02T00:00:00Z\n"
        )
        with patch.object(Path, "open", return_value=StringIO(feed)):
            iocs = load_iocs(Path("iocs.csv"))
        self.assertEqual(iocs["203.0.113.10"]["source"], "team feed | partner feed")
        self.assertEqual(iocs["203.0.113.10"]["last_seen"], "2025-01-01T00:00:00+00:00 | 2025-01-02T00:00:00+00:00")
        invalid = "indicator,type\n203.0.113.10,domain\n"
        with patch.object(Path, "open", return_value=StringIO(invalid)):
            with self.assertRaisesRegex(ValueError, "does not match"):
                load_iocs(Path("bad-iocs.csv"))

    def test_html_report_escapes_script_text_in_source_names(self) -> None:
        flow = analyze([demo_flow(1, datetime(2025, 1, 1, tzinfo=timezone.utc))])[0]
        from nth_signal.report import report_payload

        report = render_html(report_payload([flow], "</script><script>alert(1)", "CSV"))
        self.assertIn("\\u003c/script\\u003e", report)
        self.assertNotIn("</script><script>alert(1)", report)

    def test_html_report_contains_controls_used_by_its_script(self) -> None:
        flow = analyze([demo_flow(1, datetime(2025, 1, 1, tzinfo=timezone.utc), 4444)])[0]
        parser = ElementIds()
        payload = report_payload([flow], "capture.csv", "CSV")
        html_report = render_html(payload)
        parser.feed(html_report)
        self.assertTrue({"report-data", "caseStatus", "caseNotes", "caseExport", "printReport", "search", "body"}.issubset(parser.ids))
        self.assertEqual(payload["findings"][0]["finding_id"], "NTH-FND-00001")
        self.assertIn("<th>Severity</th>", html_report)
        self.assertIn("<th>Confidence</th>", html_report)
        self.assertIn("<th>Priority</th>", html_report)


if __name__ == "__main__":
    unittest.main()
