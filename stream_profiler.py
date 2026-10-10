"""
NetPacket Inspector - IP & Conversation Stream Profiler
Groups packet captures into conversational streams and detailed IP endpoint profiles with threat scoring.
"""

from collections import defaultdict, Counter
from typing import List, Dict, Any, Tuple
from pcap_parser import ParsedPacket
from threat_detector import ThreatDetector, ThreatAlert


class IPProfile:
    """Comprehensive behavioral and forensic profile of a single IP endpoint."""

    def __init__(self, ip: str):
        self.ip = ip
        self.packets_sent = 0
        self.packets_recv = 0
        self.bytes_sent = 0
        self.bytes_recv = 0
        self.protocols = Counter()
        self.ports_used = set()
        self.communicated_ips = set()
        self.threat_score = 0  # 0 (Clean) to 100 (Critical)
        self.threat_level = "CLEAN"  # CLEAN, SUSPICIOUS, MALICIOUS
        self.associated_alerts: List[str] = []

    def to_dict(self) -> Dict[str, Any]:
        return {
            "IP": self.ip,
            "Total_Packets": self.packets_sent + self.packets_recv,
            "Packets_Sent": self.packets_sent,
            "Packets_Recv": self.packets_recv,
            "Total_Bytes": self.bytes_sent + self.bytes_recv,
            "Bytes_Sent": self.bytes_sent,
            "Bytes_Recv": self.bytes_recv,
            "Protocols": dict(self.protocols),
            "Ports_Count": len(self.ports_used),
            "Peers_Count": len(self.communicated_ips),
            "Threat_Score": self.threat_score,
            "Threat_Level": self.threat_level,
            "Associated_Alerts": self.associated_alerts
        }


class NetworkConversationStream:
    """Represents a bidirectional TCP/UDP conversation between two socket endpoints."""

    def __init__(self, stream_id: int, client_ip: str, client_port: int, server_ip: str, server_port: int, protocol: str):
        self.stream_id = stream_id
        self.client_ip = client_ip
        self.client_port = client_port
        self.server_ip = server_ip
        self.server_port = server_port
        self.protocol = protocol
        self.packets: List[ParsedPacket] = []
        self.bytes_client_to_server = 0
        self.bytes_server_to_client = 0
        self.start_time: float = 0.0
        self.end_time: float = 0.0
        self.payload_client = bytearray()
        self.payload_server = bytearray()

    def add_packet(self, packet: ParsedPacket):
        if not self.packets:
            self.start_time = packet.timestamp
        self.end_time = packet.timestamp
        self.packets.append(packet)

        # Distinguish direction
        is_c2s = (packet.src == self.client_ip and packet.src_port == self.client_port)
        if is_c2s:
            self.bytes_client_to_server += packet.captured_length
            if len(self.payload_client) < 10000:
                self.payload_client.extend(packet.raw_data[min(54, len(packet.raw_data)):])
        else:
            self.bytes_server_to_client += packet.captured_length
            if len(self.payload_server) < 10000:
                self.payload_server.extend(packet.raw_data[min(54, len(packet.raw_data)):])

    def get_summary(self) -> Dict[str, Any]:
        duration = max(0.0001, self.end_time - self.start_time)
        return {
            "Stream_ID": self.stream_id,
            "Protocol": self.protocol,
            "Client": f"{self.client_ip}:{self.client_port}",
            "Server": f"{self.server_ip}:{self.server_port}",
            "Packet_Count": len(self.packets),
            "Total_Bytes": self.bytes_client_to_server + self.bytes_server_to_client,
            "Duration_Seconds": round(duration, 4),
            "Client_Payload_Preview": self.payload_client[:200].decode("latin-1", errors="replace"),
            "Server_Payload_Preview": self.payload_server[:200].decode("latin-1", errors="replace")
        }


class StreamProfiler:
    """Orchestrates stream reconstruction and IP profile matrix generation."""

    def __init__(self, packets: List[ParsedPacket], alerts: List[ThreatAlert] = None):
        self.packets = packets
        self.alerts = alerts or []
        self.ip_profiles: Dict[str, IPProfile] = {}
        self.streams: List[NetworkConversationStream] = []

        self._build_profiles()
        self._reconstruct_streams()
        self._compute_threat_scores()

    def _build_profiles(self):
        """Builds profile for every encountered IP address."""
        for p in self.packets:
            if not p.src or p.src == "Unknown" or not p.dst or p.dst == "Unknown":
                continue

            if p.src not in self.ip_profiles:
                self.ip_profiles[p.src] = IPProfile(p.src)
            if p.dst not in self.ip_profiles:
                self.ip_profiles[p.dst] = IPProfile(p.dst)

            src_prof = self.ip_profiles[p.src]
            dst_prof = self.ip_profiles[p.dst]

            src_prof.packets_sent += 1
            src_prof.bytes_sent += p.captured_length
            src_prof.protocols[p.protocol] += 1
            src_prof.communicated_ips.add(p.dst)
            if p.src_port:
                src_prof.ports_used.add(p.src_port)

            dst_prof.packets_recv += 1
            dst_prof.bytes_recv += p.captured_length
            dst_prof.protocols[p.protocol] += 1
            dst_prof.communicated_ips.add(p.src)
            if p.dst_port:
                dst_prof.ports_used.add(p.dst_port)

    def _reconstruct_streams(self):
        """Groups packets into 4-tuple conversation streams (IP A:Port A <-> IP B:Port B)."""
        stream_map: Dict[Tuple, NetworkConversationStream] = {}
        stream_counter = 0

        for p in self.packets:
            if not p.src_port or not p.dst_port or not p.src or not p.dst:
                continue

            # Bidirectional stream key
            key1 = (p.src, p.src_port, p.dst, p.dst_port, p.protocol)
            key2 = (p.dst, p.dst_port, p.src, p.src_port, p.protocol)

            if key1 in stream_map:
                stream_map[key1].add_packet(p)
            elif key2 in stream_map:
                stream_map[key2].add_packet(p)
            else:
                stream = NetworkConversationStream(
                    stream_id=stream_counter,
                    client_ip=p.src,
                    client_port=p.src_port,
                    server_ip=p.dst,
                    server_port=p.dst_port,
                    protocol=p.protocol
                )
                stream.add_packet(p)
                stream_map[key1] = stream
                stream_counter += 1

        self.streams = list(stream_map.values())

    def _compute_threat_scores(self):
        """Scores each IP endpoint based on forensic alerts and traffic anomalies."""
        for alert in self.alerts:
            src_ip = alert.source_ip
            weight = {"CRITICAL": 50, "HIGH": 30, "MEDIUM": 15, "LOW": 5, "INFO": 2}.get(alert.severity, 0)

            # Match IP profile
            for ip, prof in self.ip_profiles.items():
                if ip in src_ip:
                    prof.threat_score = min(100, prof.threat_score + weight)
                    prof.associated_alerts.append(f"[{alert.severity}] {alert.title}")

        for prof in self.ip_profiles.values():
            if prof.threat_score >= 40:
                prof.threat_level = "MALICIOUS"
            elif prof.threat_score >= 15:
                prof.threat_level = "SUSPICIOUS"
            else:
                prof.threat_level = "CLEAN"

    def get_all_ip_profiles(self) -> List[Dict[str, Any]]:
        """Returns sorted list of IP profiles by threat score then volume."""
        profs = [p.to_dict() for p in self.ip_profiles.values()]
        profs.sort(key=lambda x: (x["Threat_Score"], x["Total_Packets"]), reverse=True)
        return profs

    def get_all_streams(self) -> List[Dict[str, Any]]:
        """Returns reconstructed conversation streams."""
        streams = [s.get_summary() for s in self.streams]
        streams.sort(key=lambda s: s["Packet_Count"], reverse=True)
        return streams
