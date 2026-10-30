"""Dependency-free classic PCAP and PCAPNG flow extraction.

The parser supports Ethernet (including VLAN tags), raw IPv4/IPv6, Linux cooked
capture, TCP, and UDP. It intentionally does not reassemble IP fragments or
decode encrypted/application payloads.
"""

from __future__ import annotations

import ipaddress
import struct
from collections import OrderedDict
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterator

Packet = tuple[float, bytes, int]


def _pcap_packets(data: bytes) -> Iterator[Packet]:
    if len(data) < 24:
        raise ValueError("PCAP file is shorter than its global header.")
    magic = data[:4]
    formats = {
        b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
        b"\xa1\xb2\xc3\xd4": (">", 1e-6),
        b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
        b"\xa1\xb2\x3c\x4d": (">", 1e-9),
    }
    if magic not in formats:
        raise ValueError("Unrecognized classic PCAP byte order or timestamp format.")
    endian, resolution = formats[magic]
    major, minor, _, _, snap_length, network = struct.unpack_from(endian + "HHIIII", data, 4)
    if major != 2 or minor > 4:
        raise ValueError(f"Unsupported PCAP version {major}.{minor}.")
    if snap_length == 0:
        raise ValueError("PCAP snap length cannot be zero.")
    network &= 0xFFFF  # Newer PCAP writers may store flags in the upper bits.
    offset = 24
    while offset < len(data):
        if offset + 16 > len(data):
            raise ValueError("Truncated PCAP packet header.")
        seconds, fraction, captured, _ = struct.unpack_from(endian + "IIII", data, offset)
        offset += 16
        if fraction >= round(1 / resolution):
            raise ValueError("PCAP packet timestamp fraction is out of range.")
        if captured > snap_length:
            raise ValueError("PCAP packet size exceeds the file's snap length.")
        if captured > len(data) - offset:
            raise ValueError("Truncated PCAP packet data.")
        yield seconds + fraction * resolution, data[offset:offset + captured], network
        offset += captured


def _pcapng_packets(data: bytes) -> Iterator[Packet]:
    offset = 0
    endian: str | None = None
    interfaces: list[tuple[int, float]] = []
    last_timestamp = 0.0
    while offset < len(data):
        if offset + 12 > len(data):
            raise ValueError("Truncated PCAPNG block header.")
        block_type_bytes = data[offset:offset + 4]
        if block_type_bytes == b"\x0a\x0d\x0d\x0a":
            if offset + 12 > len(data):
                raise ValueError("Truncated PCAPNG section header.")
            bom = data[offset + 8:offset + 12]
            if bom == b"\x4d\x3c\x2b\x1a":
                endian = "<"
            elif bom == b"\x1a\x2b\x3c\x4d":
                endian = ">"
            else:
                endian = None
            if endian is None:
                raise ValueError("Invalid PCAPNG byte-order magic.")
            block_type = 0x0A0D0D0A
            block_length = struct.unpack_from(endian + "I", data, offset + 4)[0]
            interfaces = []
            last_timestamp = 0.0
        else:
            if endian is None:
                raise ValueError("PCAPNG section header is missing.")
            block_type, block_length = struct.unpack_from(endian + "II", data, offset)
        if block_length < 12 or block_length % 4 or offset + block_length > len(data):
            raise ValueError("Invalid or truncated PCAPNG block length.")
        block = data[offset:offset + block_length]
        if struct.unpack_from(endian + "I", block, block_length - 4)[0] != block_length:
            raise ValueError("PCAPNG block length trailer does not match its header.")
        if block_type == 1:  # Interface Description Block
            if block_length < 20:
                raise ValueError("Truncated PCAPNG interface description.")
            linktype = struct.unpack_from(endian + "H", block, 8)[0]
            resolution = 1e-6
            pos = 16
            while pos + 4 <= block_length - 4:
                code, size = struct.unpack_from(endian + "HH", block, pos)
                pos += 4
                if code == 0:
                    break
                if pos + size > block_length - 4:
                    raise ValueError("Invalid PCAPNG interface option length.")
                value = block[pos:pos + size]
                if code == 9 and size == 1:  # if_tsresol
                    exponent = value[0] & 0x7F
                    resolution = (2.0 ** -exponent) if value[0] & 0x80 else (10.0 ** -exponent)
                pos += (size + 3) & ~3
            interfaces.append((linktype, resolution))
        elif block_type == 6:  # Enhanced Packet Block
            if block_length < 32:
                raise ValueError("Truncated PCAPNG enhanced packet block.")
            iface, hi, lo, captured, _ = struct.unpack_from(endian + "IIIII", block, 8)
            packet_end = 28 + captured
            if iface >= len(interfaces) or packet_end > block_length - 4:
                raise ValueError("Invalid PCAPNG packet interface or captured length.")
            linktype, resolution = interfaces[iface]
            ticks = (hi << 32) | lo
            last_timestamp = ticks * resolution
            yield last_timestamp, block[28:28 + captured], linktype
        elif block_type == 3:  # Simple Packet Block has no timestamp or interface id.
            if block_length < 16 or not interfaces:
                raise ValueError("Invalid PCAPNG simple packet block.")
            captured = min(struct.unpack_from(endian + "I", block, 8)[0], block_length - 16)
            yield last_timestamp, block[12:12 + captured], interfaces[0][0]
        offset += block_length


def _transport_packet(
    packet: bytes,
    linktype: int,
) -> tuple[str, str, int, int, str, int, int, int] | None:
    """Return endpoints, protocol, IP size, and transport payload bounds."""
    offset = 0
    ethertype = None
    if linktype == 1:  # Ethernet
        if len(packet) < 14:
            return None
        ethertype = struct.unpack_from("!H", packet, 12)[0]
        offset = 14
        while ethertype in {0x8100, 0x88A8, 0x9100}:
            if len(packet) < offset + 4:
                return None
            ethertype = struct.unpack_from("!H", packet, offset + 2)[0]
            offset += 4
    elif linktype == 113:  # Linux cooked capture v1
        if len(packet) < 16:
            return None
        ethertype = struct.unpack_from("!H", packet, 14)[0]
        offset = 16
    elif linktype == 276:  # Linux cooked capture v2
        if len(packet) < 20:
            return None
        ethertype = struct.unpack_from("!H", packet, 0)[0]
        offset = 20
    elif linktype in {12, 101}:  # DLT_RAW variants
        if not packet:
            return None
        ethertype = 0x0800 if packet[0] >> 4 == 4 else 0x86DD if packet[0] >> 4 == 6 else None
    elif linktype == 228:  # DLT_IPV4
        ethertype = 0x0800
    elif linktype == 229:  # DLT_IPV6
        ethertype = 0x86DD
    else:
        return None

    if ethertype == 0x0800:
        if len(packet) < offset + 20 or packet[offset] >> 4 != 4:
            return None
        ihl = (packet[offset] & 0x0F) * 4
        if ihl < 20 or len(packet) < offset + ihl:
            return None
        total_length = struct.unpack_from("!H", packet, offset + 2)[0]
        if total_length < ihl:
            return None
        frag = struct.unpack_from("!H", packet, offset + 6)[0]
        if frag & 0x1FFF:  # Non-initial fragment: transport header is absent.
            return None
        proto = packet[offset + 9]
        src = str(ipaddress.IPv4Address(packet[offset + 12:offset + 16]))
        dst = str(ipaddress.IPv4Address(packet[offset + 16:offset + 20]))
        transport = offset + ihl
    elif ethertype == 0x86DD:
        if len(packet) < offset + 40 or packet[offset] >> 4 != 6:
            return None
        payload_len = struct.unpack_from("!H", packet, offset + 4)[0]
        proto = packet[offset + 6]
        src = str(ipaddress.IPv6Address(packet[offset + 8:offset + 24]))
        dst = str(ipaddress.IPv6Address(packet[offset + 24:offset + 40]))
        total_length = 40 + payload_len
        transport = offset + 40
        # Walk common IPv6 extension headers to the transport layer.
        while proto in {0, 43, 60, 44, 51}:
            if len(packet) < transport + 2:
                return None
            next_proto = packet[transport]
            if proto == 44:
                if len(packet) < transport + 8:
                    return None
                frag = struct.unpack_from("!H", packet, transport + 2)[0]
                if frag & 0xFFF8:
                    return None
                size = 8
            elif proto == 51:
                size = (packet[transport + 1] + 2) * 4
            else:
                size = (packet[transport + 1] + 1) * 8
            if len(packet) < transport + size:
                return None
            transport += size
            proto = next_proto
    else:
        return None

    packet_end = offset + total_length
    if proto not in {6, 17} or len(packet) < transport + 4 or transport + 4 > packet_end:
        return None
    sport, dport = struct.unpack_from("!HH", packet, transport)
    protocol_header_length = 8
    if proto == 6:
        if len(packet) < transport + 20 or transport + 20 > packet_end:
            return None
        protocol_header_length = (packet[transport + 12] >> 4) * 4
        if protocol_header_length < 20 or transport + protocol_header_length > packet_end:
            return None
    elif len(packet) < transport + 8 or transport + 8 > packet_end:
        return None
    payload_offset = transport + protocol_header_length
    payload_length = max(0, total_length - (transport - offset) - protocol_header_length)
    return src, dst, sport, dport, "TCP" if proto == 6 else "UDP", total_length, payload_offset, payload_length


def _dns_query(payload: bytes) -> str | None:
    """Read one uncompressed question name from a DNS request packet."""
    if len(payload) < 17:
        return None
    flags, question_count = struct.unpack_from("!HH", payload, 2)
    if flags & 0x8000 or question_count == 0:
        return None
    labels = []
    offset = 12
    while offset < len(payload):
        size = payload[offset]
        offset += 1
        if size == 0:
            if not labels or offset + 4 > len(payload):
                return None
            return ".".join(labels).casefold()
        if size & 0xC0 or size > 63 or offset + size > len(payload):
            return None
        try:
            labels.append(payload[offset:offset + size].decode("ascii"))
        except UnicodeDecodeError:
            return None
        offset += size
        if len(labels) > 127:
            return None
    return None


def read_pcap(path: Path) -> list[dict]:
    """Convert packet records into bidirectional flow rows for the rule engine."""
    data = path.read_bytes()
    packets = _pcapng_packets(data) if data[:4] == b"\x0a\x0d\x0d\x0a" else _pcap_packets(data)
    flows: OrderedDict[tuple, dict] = OrderedDict()
    packet_count = 0
    for timestamp, packet, linktype in packets:
        decoded = _transport_packet(packet, linktype)
        if decoded is None:
            continue
        src, dst, sport, dport, proto, packet_length, payload_offset, payload_length = decoded
        endpoint_a, endpoint_b = (src, sport), (dst, dport)
        key = (proto, *sorted((endpoint_a, endpoint_b)))
        flow = flows.get(key)
        if flow is None:
            flow = {"id": len(flows) + 1, "timestamp": None,
                    "_first": timestamp, "_last": timestamp, "_first_endpoint": endpoint_a,
                    "src_ip": src, "src_port": sport,
                    "dst_ip": dst, "dst_port": dport, "protocol": proto, "service": "", "duration": 0.0,
                    "src_bytes": 0.0, "dst_bytes": 0.0, "src_packets": 0.0, "dst_packets": 0.0,
                    "conn_state": "PCAP", "signals": [], "score": 0, "dns_queries": []}
            flows[key] = flow
        flow["_first"] = min(flow["_first"], timestamp)
        flow["_last"] = max(flow["_last"], timestamp)
        origin = endpoint_a == flow["_first_endpoint"]
        byte_key, packet_key = ("src_bytes", "src_packets") if origin else ("dst_bytes", "dst_packets")
        flow[byte_key] += packet_length
        flow[packet_key] += 1
        if proto == "UDP" and (sport == 53 or dport == 53):
            query = _dns_query(packet[payload_offset:payload_offset + payload_length])
            if query and query not in flow["dns_queries"]:
                flow["dns_queries"].append(query)
        packet_count += 1
    if not packet_count:
        raise ValueError("No TCP or UDP IPv4/IPv6 packets were found. Check the capture link type and contents.")
    result = []
    for flow in flows.values():
        first_seen = flow.pop("_first")
        last_seen = flow.pop("_last")
        try:
            flow["timestamp"] = datetime.fromtimestamp(first_seen, timezone.utc)
        except (OverflowError, OSError, ValueError) as exc:
            raise ValueError("PCAP packet timestamp is outside the supported date range.") from exc
        flow["duration"] = max(0.0, last_seen - first_seen)
        flow.pop("_first_endpoint")
        # `timestamp` above remains the first packet time for report timeline.
        result.append(flow)
    return result
