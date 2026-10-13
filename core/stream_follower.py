"""
NetPacket Inspector - Wireshark-Style TCP & HTTP Stream Follower
Reassembles bidirectional conversation streams, decodes payload chunks, and tracks direction.
"""

from typing import List, Dict, Any, Optional, Tuple
from core.pcap_parser import ParsedPacket


class StreamChunk:
    """Represents a single payload transmission chunk in a conversation."""

    def __init__(self, packet_num: int, rel_time: float, direction: str, sender_endpoint: str, receiver_endpoint: str, data: bytes):
        self.packet_num = packet_num
        self.rel_time = rel_time
        self.direction = direction  # "CLIENT_TO_SERVER" or "SERVER_TO_CLIENT"
        self.sender_endpoint = sender_endpoint
        self.receiver_endpoint = receiver_endpoint
        self.data = data
        self.text = data.decode("latin-1", errors="replace")


class StreamFollower:
    """Reassembles and reconstructs entire conversation sessions (TCP/UDP/HTTP)."""

    @staticmethod
    def follow_stream_for_packet(packet: ParsedPacket, all_packets: List[ParsedPacket]) -> Dict[str, Any]:
        """Finds and reconstructs the full bidirectional stream matching the selected packet."""
        if not packet.src_port or not packet.dst_port:
            return {
                "Stream_Found": False,
                "Message": "Selected packet is not a Layer 4 TCP/UDP transport packet.",
                "Chunks": []
            }

        endpoint_a = (packet.src, packet.src_port)
        endpoint_b = (packet.dst, packet.dst_port)
        proto = packet.protocol

        client_endpoint = f"{endpoint_a[0]}:{endpoint_a[1]}"
        server_endpoint = f"{endpoint_b[0]}:{endpoint_b[1]}"

        matching_packets: List[ParsedPacket] = []

        for p in all_packets:
            if not p.src_port or not p.dst_port:
                continue

            curr_a = (p.src, p.src_port)
            curr_b = (p.dst, p.dst_port)

            # Match bidirectional pair
            if (curr_a == endpoint_a and curr_b == endpoint_b) or (curr_a == endpoint_b and curr_b == endpoint_a):
                matching_packets.append(p)

        if not matching_packets:
            return {"Stream_Found": False, "Message": "No conversation stream found.", "Chunks": []}

        # Sort by timestamp / packet number
        matching_packets.sort(key=lambda x: x.packet_num)

        chunks: List[StreamChunk] = []
        total_client_bytes = 0
        total_server_bytes = 0

        for p in matching_packets:
            # Extract application payload (past Ethernet 14 + IP 20 + TCP/UDP 20/8 header)
            payload = b""
            for layer in p.layers:
                lname = layer.get("LayerName", "")
                if "TCP" in lname or "UDP" in lname:
                    header_len = 20
                    if "Header_Length" in layer:
                        try:
                            header_len = int(layer["Header_Length"].split()[0])
                        except Exception:
                            header_len = 20
                    # Slice payload
                    payload_offset = 14 + 20 + header_len
                    if len(p.raw_data) > payload_offset:
                        payload = p.raw_data[payload_offset:]
                    elif len(p.raw_data) > 54:
                        payload = p.raw_data[54:]
                    break

            if not payload and len(p.raw_data) > 54:
                payload = p.raw_data[54:]

            if payload:
                is_c2s = (p.src == endpoint_a[0] and p.src_port == endpoint_a[1])
                direction = "CLIENT_TO_SERVER" if is_c2s else "SERVER_TO_CLIENT"

                if is_c2s:
                    total_client_bytes += len(payload)
                else:
                    total_server_bytes += len(payload)

                chunks.append(StreamChunk(
                    packet_num=p.packet_num,
                    rel_time=p.rel_time,
                    direction=direction,
                    sender_endpoint=f"{p.src}:{p.src_port}",
                    receiver_endpoint=f"{p.dst}:{p.dst_port}",
                    data=payload
                ))

        start_time = matching_packets[0].rel_time
        end_time = matching_packets[-1].rel_time

        return {
            "Stream_Found": True,
            "Protocol": proto,
            "Client": client_endpoint,
            "Server": server_endpoint,
            "Total_Packets": len(matching_packets),
            "Duration_Seconds": round(max(0.0001, end_time - start_time), 4),
            "Client_Bytes": total_client_bytes,
            "Server_Bytes": total_server_bytes,
            "Chunks_Count": len(chunks),
            "Chunks": chunks
        }
