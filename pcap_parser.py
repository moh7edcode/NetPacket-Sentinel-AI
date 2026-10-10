"""
NetPacket Inspector - Core Packet Parser Engine
Pure Python PCAP and PCAPNG dissection engine supporting Ethernet, ARP, IPv4, IPv6, ICMP, TCP, UDP, DNS, HTTP, TLS, etc.
"""

import struct
import socket
import datetime
from typing import List, Dict, Any, Optional, Tuple


def mac_to_str(mac_bytes: bytes) -> str:
    """Format 6 bytes into standard MAC address string (e.g. 00:1A:2B:3C:4D:5E)."""
    return ":".join(f"{b:02x}" for b in mac_bytes)


def ip4_to_str(ip_bytes: bytes) -> str:
    """Format 4 bytes into IPv4 string (e.g. 192.168.1.1)."""
    return socket.inet_ntoa(ip_bytes)


def ip6_to_str(ip_bytes: bytes) -> str:
    """Format 16 bytes into IPv6 string."""
    try:
        return socket.inet_ntop(socket.AF_INET6, ip_bytes)
    except Exception:
        return ":".join(f"{ip_bytes[i:i+2].hex()}" for i in range(0, 16, 2))


def bytes_to_hex_dump(data: bytes, bytes_per_line: int = 16) -> str:
    """Generate Wireshark-style Hex + ASCII dump."""
    lines = []
    for i in range(0, len(data), bytes_per_line):
        chunk = data[i:i + bytes_per_line]
        hex_bytes = " ".join(f"{b:02x}" for b in chunk)
        # Pad hex display for uniform spacing
        hex_bytes = hex_bytes.ljust(bytes_per_line * 3 - 1)
        ascii_bytes = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"{i:04x}   {hex_bytes}   |{ascii_bytes}|")
    return "\n".join(lines)


class PacketDissector:
    """Dissects raw packet bytes into structured multi-layer headers and fields."""

    @staticmethod
    def dissect_ethernet(raw_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Dissects Ethernet II Header (14 bytes)."""
        if len(raw_bytes) < 14:
            return {"Layer": "Ethernet", "Error": "Truncated Frame"}, raw_bytes

        dst_mac = mac_to_str(raw_bytes[0:6])
        src_mac = mac_to_str(raw_bytes[6:12])
        eth_type = struct.unpack("!H", raw_bytes[12:14])[0]

        payload_offset = 14
        vlan_info = None
        if eth_type == 0x8100 and len(raw_bytes) >= 18:
            vlan_tci = struct.unpack("!H", raw_bytes[14:16])[0]
            vlan_id = vlan_tci & 0x0FFF
            vlan_priority = (vlan_tci >> 13) & 0x07
            vlan_info = {"VLAN_ID": vlan_id, "Priority": vlan_priority}
            eth_type = struct.unpack("!H", raw_bytes[16:18])[0]
            payload_offset = 18

        type_names = {
            0x0800: "IPv4",
            0x0806: "ARP",
            0x86DD: "IPv6",
            0x8100: "802.1Q VLAN",
            0x88CC: "LLDP"
        }

        layer_data = {
            "LayerName": "Ethernet II",
            "Destination_MAC": dst_mac,
            "Source_MAC": src_mac,
            "EtherType": f"0x{eth_type:04x} ({type_names.get(eth_type, 'Unknown')})",
            "EtherType_Code": eth_type
        }
        if vlan_info:
            layer_data["VLAN"] = vlan_info

        return layer_data, raw_bytes[payload_offset:]

    @staticmethod
    def dissect_arp(raw_bytes: bytes) -> Dict[str, Any]:
        """Dissects ARP packet (28 bytes)."""
        if len(raw_bytes) < 28:
            return {"LayerName": "ARP", "Error": "Truncated ARP packet"}

        hw_type, proto_type, hw_len, proto_len, opcode = struct.unpack("!HHBBH", raw_bytes[0:8])
        sender_mac = mac_to_str(raw_bytes[8:14])
        sender_ip = ip4_to_str(raw_bytes[14:18])
        target_mac = mac_to_str(raw_bytes[18:24])
        target_ip = ip4_to_str(raw_bytes[24:28])

        opcodes = {1: "ARP Request (who-has)", 2: "ARP Reply (is-at)", 3: "RARP Request", 4: "RARP Reply"}

        return {
            "LayerName": "Address Resolution Protocol (ARP)",
            "Hardware_Type": f"{hw_type} ({'Ethernet' if hw_type == 1 else 'Other'})",
            "Protocol_Type": f"0x{proto_type:04x} ({'IPv4' if proto_type == 0x0800 else 'Other'})",
            "Hardware_Size": hw_len,
            "Protocol_Size": proto_len,
            "Opcode": f"{opcode} ({opcodes.get(opcode, 'Unknown')})",
            "Sender_MAC": sender_mac,
            "Sender_IP": sender_ip,
            "Target_MAC": target_mac,
            "Target_IP": target_ip,
            "Summary": f"{opcodes.get(opcode, 'ARP')} {target_ip} tell {sender_ip}"
        }

    @staticmethod
    def dissect_ipv4(raw_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Dissects IPv4 Header."""
        if len(raw_bytes) < 20:
            return {"LayerName": "IPv4", "Error": "Truncated IPv4 Header"}, raw_bytes

        ver_ihl = raw_bytes[0]
        version = ver_ihl >> 4
        ihl = (ver_ihl & 0x0F) * 4

        if len(raw_bytes) < ihl:
            return {"LayerName": "IPv4", "Error": "Header shorter than IHL"}, raw_bytes

        tos, total_length, identification, flags_frag, ttl, protocol, checksum = struct.unpack(
            "!BHHHBBH", raw_bytes[1:12]
        )
        src_ip = ip4_to_str(raw_bytes[12:16])
        dst_ip = ip4_to_str(raw_bytes[16:20])

        reserved_flag = bool(flags_frag & 0x8000)
        df_flag = bool(flags_frag & 0x4000)
        mf_flag = bool(flags_frag & 0x2000)
        frag_offset = (flags_frag & 0x1FFF) * 8

        proto_names = {
            1: "ICMP",
            2: "IGMP",
            6: "TCP",
            17: "UDP",
            47: "GRE",
            50: "ESP",
            51: "AH",
            89: "OSPF"
        }

        layer_data = {
            "LayerName": "Internet Protocol Version 4",
            "Version": version,
            "Header_Length": f"{ihl} bytes",
            "DSCP_ECN": f"0x{tos:02x}",
            "Total_Length": total_length,
            "Identification": f"0x{identification:04x} ({identification})",
            "Flags": {
                "Reserved": reserved_flag,
                "Don't_Fragment_(DF)": df_flag,
                "More_Fragments_(MF)": mf_flag
            },
            "Fragment_Offset": frag_offset,
            "Time_To_Live_(TTL)": ttl,
            "Protocol": f"{protocol} ({proto_names.get(protocol, 'Unknown')})",
            "Protocol_Code": protocol,
            "Header_Checksum": f"0x{checksum:04x}",
            "Source_IP": src_ip,
            "Destination_IP": dst_ip
        }

        payload = raw_bytes[ihl:]
        return layer_data, payload

    @staticmethod
    def dissect_ipv6(raw_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Dissects IPv6 Header (40 bytes)."""
        if len(raw_bytes) < 40:
            return {"LayerName": "IPv6", "Error": "Truncated IPv6 Header"}, raw_bytes

        first_word = struct.unpack("!I", raw_bytes[0:4])[0]
        version = (first_word >> 28) & 0x0F
        traffic_class = (first_word >> 20) & 0xFF
        flow_label = first_word & 0xFFFFF

        payload_length, next_header, hop_limit = struct.unpack("!HBB", raw_bytes[4:8])
        src_ip = ip6_to_str(raw_bytes[8:24])
        dst_ip = ip6_to_str(raw_bytes[24:40])

        proto_names = {
            1: "ICMP",
            6: "TCP",
            17: "UDP",
            58: "ICMPv6"
        }

        layer_data = {
            "LayerName": "Internet Protocol Version 6",
            "Version": version,
            "Traffic_Class": f"0x{traffic_class:02x}",
            "Flow_Label": f"0x{flow_label:05x}",
            "Payload_Length": f"{payload_length} bytes",
            "Next_Header": f"{next_header} ({proto_names.get(next_header, 'Unknown')})",
            "Next_Header_Code": next_header,
            "Hop_Limit": hop_limit,
            "Source_IP": src_ip,
            "Destination_IP": dst_ip
        }

        return layer_data, raw_bytes[40:]

    @staticmethod
    def dissect_tcp(raw_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Dissects TCP Header."""
        if len(raw_bytes) < 20:
            return {"LayerName": "TCP", "Error": "Truncated TCP Header"}, raw_bytes

        src_port, dst_port, seq, ack, offset_reserved_flags, window, checksum, urgent = struct.unpack(
            "!HHIIHHHH", raw_bytes[0:20]
        )
        data_offset = (offset_reserved_flags >> 12) * 4
        flags = offset_reserved_flags & 0x01FF

        flag_cwr = bool(flags & 0x0080)
        flag_ece = bool(flags & 0x0040)
        flag_urg = bool(flags & 0x0020)
        flag_ack = bool(flags & 0x0010)
        flag_psh = bool(flags & 0x0008)
        flag_rst = bool(flags & 0x0004)
        flag_syn = bool(flags & 0x0002)
        flag_fin = bool(flags & 0x0001)

        active_flags = []
        if flag_syn: active_flags.append("SYN")
        if flag_ack: active_flags.append("ACK")
        if flag_fin: active_flags.append("FIN")
        if flag_rst: active_flags.append("RST")
        if flag_psh: active_flags.append("PSH")
        if flag_urg: active_flags.append("URG")

        flags_str = "[" + ", ".join(active_flags) + "]" if active_flags else "[None]"

        layer_data = {
            "LayerName": "Transmission Control Protocol (TCP)",
            "Source_Port": src_port,
            "Destination_Port": dst_port,
            "Sequence_Number": seq,
            "Acknowledgment_Number": ack,
            "Header_Length": f"{data_offset} bytes",
            "Flags_Summary": flags_str,
            "Flags_Detail": {
                "CWR": flag_cwr,
                "ECE": flag_ece,
                "URG": flag_urg,
                "ACK": flag_ack,
                "PSH": flag_psh,
                "RST": flag_rst,
                "SYN": flag_syn,
                "FIN": flag_fin
            },
            "Window_Size": window,
            "Checksum": f"0x{checksum:04x}",
            "Urgent_Pointer": urgent
        }

        payload = raw_bytes[data_offset:] if len(raw_bytes) >= data_offset else b""
        return layer_data, payload

    @staticmethod
    def dissect_udp(raw_bytes: bytes) -> Tuple[Dict[str, Any], bytes]:
        """Dissects UDP Header (8 bytes)."""
        if len(raw_bytes) < 8:
            return {"LayerName": "UDP", "Error": "Truncated UDP Header"}, raw_bytes

        src_port, dst_port, length, checksum = struct.unpack("!HHHH", raw_bytes[0:8])

        layer_data = {
            "LayerName": "User Datagram Protocol (UDP)",
            "Source_Port": src_port,
            "Destination_Port": dst_port,
            "Length": f"{length} bytes",
            "Checksum": f"0x{checksum:04x}"
        }

        payload = raw_bytes[8:]
        return layer_data, payload

    @staticmethod
    def dissect_icmp(raw_bytes: bytes) -> Dict[str, Any]:
        """Dissects ICMP Header."""
        if len(raw_bytes) < 8:
            return {"LayerName": "ICMP", "Error": "Truncated ICMP Header"}

        icmp_type, icmp_code, checksum, rest_of_header = struct.unpack("!BBHI", raw_bytes[0:8])

        type_map = {
            0: "Echo (ping) Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo (ping) Request",
            11: "Time-to-Live Exceeded",
            12: "Parameter Problem",
            13: "Timestamp Request",
            14: "Timestamp Reply"
        }

        layer_data = {
            "LayerName": "Internet Control Message Protocol (ICMP)",
            "Type": f"{icmp_type} ({type_map.get(icmp_type, 'Unknown')})",
            "Type_Code_Val": icmp_type,
            "Code": icmp_code,
            "Checksum": f"0x{checksum:04x}",
            "Identifier_Sequence": f"0x{rest_of_header:08x}"
        }
        return layer_data

    @staticmethod
    def dissect_dns(raw_bytes: bytes) -> Dict[str, Any]:
        """Dissects DNS Header and Query names."""
        if len(raw_bytes) < 12:
            return {"LayerName": "DNS", "Error": "Truncated DNS packet"}

        tx_id, flags, qd_count, an_count, ns_count, ar_count = struct.unpack("!HHHHHH", raw_bytes[0:12])
        is_response = bool(flags & 0x8000)
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        queries = []
        offset = 12
        try:
            for _ in range(qd_count):
                if offset >= len(raw_bytes):
                    break
                labels = []
                while offset < len(raw_bytes):
                    length = raw_bytes[offset]
                    if length == 0:
                        offset += 1
                        break
                    if length & 0xC0 == 0xC0:
                        offset += 2
                        break
                    offset += 1
                    labels.append(raw_bytes[offset:offset + length].decode("ascii", errors="replace"))
                    offset += length
                
                query_name = ".".join(labels)
                if offset + 4 <= len(raw_bytes):
                    q_type, q_class = struct.unpack("!HH", raw_bytes[offset:offset + 4])
                    offset += 4
                    qtype_map = {1: "A", 28: "AAAA", 15: "MX", 16: "TXT", 5: "CNAME", 2: "NS", 12: "PTR"}
                    queries.append(f"{query_name} ({qtype_map.get(q_type, f'Type {q_type}')})")
                else:
                    queries.append(query_name)
        except Exception:
            pass

        return {
            "LayerName": "Domain Name System (DNS)",
            "Transaction_ID": f"0x{tx_id:04x}",
            "Message_Type": "Response" if is_response else "Query",
            "Opcode": opcode,
            "Response_Code": rcode,
            "Questions_Count": qd_count,
            "Answer_RRs_Count": an_count,
            "Queries": queries if queries else ["(None)"]
        }

    @staticmethod
    def dissect_http(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Checks and parses HTTP requests and responses."""
        try:
            text = raw_bytes[:1024].decode("latin-1")
            first_line = text.split("\r\n")[0]
            http_methods = ("GET ", "POST ", "HEAD ", "PUT ", "DELETE ", "OPTIONS ", "CONNECT ", "PATCH ")
            
            if any(first_line.startswith(m) for m in http_methods):
                parts = first_line.split(" ")
                headers = {}
                for line in text.split("\r\n")[1:]:
                    if not line:
                        break
                    if ":" in line:
                        k, v = line.split(":", 1)
                        headers[k.strip()] = v.strip()

                return {
                    "LayerName": "Hypertext Transfer Protocol (HTTP)",
                    "Type": "HTTP Request",
                    "Method": parts[0],
                    "URI": parts[1] if len(parts) > 1 else "/",
                    "Version": parts[2] if len(parts) > 2 else "HTTP/1.1",
                    "Host": headers.get("Host", "(None)"),
                    "User-Agent": headers.get("User-Agent", "(None)"),
                    "Content-Type": headers.get("Content-Type", "(None)"),
                    "Content-Length": headers.get("Content-Length", "(None)"),
                    "First_Line": first_line
                }
            elif first_line.startswith("HTTP/"):
                parts = first_line.split(" ", 2)
                return {
                    "LayerName": "Hypertext Transfer Protocol (HTTP)",
                    "Type": "HTTP Response",
                    "Status_Code": parts[1] if len(parts) > 1 else "Unknown",
                    "Status_Message": parts[2] if len(parts) > 2 else "",
                    "First_Line": first_line
                }
        except Exception:
            pass
        return None

    @staticmethod
    def dissect_tls(raw_bytes: bytes) -> Optional[Dict[str, Any]]:
        """Dissects TLS / SSL Handshake ClientHello to extract SNI."""
        if len(raw_bytes) < 5:
            return None
        content_type, version, length = struct.unpack("!BHH", raw_bytes[0:5])
        if content_type == 22:  # Handshake
            handshake_type = raw_bytes[5] if len(raw_bytes) > 5 else 0
            handshake_names = {1: "Client Hello", 2: "Server Hello", 11: "Certificate"}
            sni = None
            if handshake_type == 1 and len(raw_bytes) > 43:
                try:
                    pos = 43
                    if pos < len(raw_bytes):
                        sess_len = raw_bytes[pos]
                        pos += 1 + sess_len
                    if pos + 2 <= len(raw_bytes):
                        cipher_len = struct.unpack("!H", raw_bytes[pos:pos+2])[0]
                        pos += 2 + cipher_len
                    if pos < len(raw_bytes):
                        comp_len = raw_bytes[pos]
                        pos += 1 + comp_len
                    if pos + 2 <= len(raw_bytes):
                        ext_total_len = struct.unpack("!H", raw_bytes[pos:pos+2])[0]
                        pos += 2
                        ext_end = pos + ext_total_len
                        while pos + 4 <= ext_end and pos + 4 <= len(raw_bytes):
                            ext_type, ext_len = struct.unpack("!HH", raw_bytes[pos:pos+4])
                            pos += 4
                            if ext_type == 0:
                                if pos + 5 <= len(raw_bytes):
                                    name_len = struct.unpack("!H", raw_bytes[pos+3:pos+5])[0]
                                    sni = raw_bytes[pos+5:pos+5+name_len].decode("utf-8", errors="ignore")
                                break
                            pos += ext_len
                except Exception:
                    pass

            return {
                "LayerName": "Transport Layer Security (TLS)",
                "Content_Type": "Handshake (22)",
                "Handshake_Type": f"{handshake_type} ({handshake_names.get(handshake_type, 'Other')})",
                "TLS_Version": f"0x{version:04x}",
                "Server_Name_Indication_(SNI)": sni if sni else "(None / Encrypted)"
            }
        return None


class ParsedPacket:
    """Represents a fully dissected network packet."""

    def __init__(self, packet_num: int, timestamp: float, raw_data: bytes, cap_len: int, orig_len: int, rel_time: float = 0.0):
        self.packet_num: int = packet_num
        self.timestamp: float = timestamp
        self.rel_time: float = rel_time
        self.raw_data: bytes = raw_data
        self.captured_length: int = cap_len
        self.original_length: int = orig_len

        self.layers: List[Dict[str, Any]] = []
        self.src: str = "Unknown"
        self.dst: str = "Unknown"
        self.protocol: str = "Raw Data"
        self.src_port: Optional[int] = None
        self.dst_port: Optional[int] = None
        self.info: str = ""

        self._dissect()

    def _dissect(self):
        """Perform comprehensive multi-layer dissection."""
        remaining = self.raw_data

        # 1. Layer 2: Ethernet
        eth_info, remaining = PacketDissector.dissect_ethernet(remaining)
        self.layers.append(eth_info)
        self.src = eth_info.get("Source_MAC", "Unknown")
        self.dst = eth_info.get("Destination_MAC", "Unknown")
        eth_type_code = eth_info.get("EtherType_Code", 0)

        # 2. Layer 3: ARP or IP
        l3_proto_code = None
        if eth_type_code == 0x0806:  # ARP
            arp_info = PacketDissector.dissect_arp(remaining)
            self.layers.append(arp_info)
            self.src = arp_info.get("Sender_IP", self.src)
            self.dst = arp_info.get("Target_IP", self.dst)
            self.protocol = "ARP"
            self.info = arp_info.get("Summary", "ARP")
            return

        elif eth_type_code == 0x0800:  # IPv4
            ip_info, remaining = PacketDissector.dissect_ipv4(remaining)
            self.layers.append(ip_info)
            self.src = ip_info.get("Source_IP", self.src)
            self.dst = ip_info.get("Destination_IP", self.dst)
            self.protocol = "IPv4"
            l3_proto_code = ip_info.get("Protocol_Code")

        elif eth_type_code == 0x86DD:  # IPv6
            ip_info, remaining = PacketDissector.dissect_ipv6(remaining)
            self.layers.append(ip_info)
            self.src = ip_info.get("Source_IP", self.src)
            self.dst = ip_info.get("Destination_IP", self.dst)
            self.protocol = "IPv6"
            l3_proto_code = ip_info.get("Next_Header_Code")

        # 3. Layer 4: TCP, UDP, ICMP
        if l3_proto_code == 1:  # ICMP
            icmp_info = PacketDissector.dissect_icmp(remaining)
            self.layers.append(icmp_info)
            self.protocol = "ICMP"
            self.info = icmp_info.get("Type", "ICMP")
            return

        elif l3_proto_code == 6:  # TCP
            tcp_info, remaining = PacketDissector.dissect_tcp(remaining)
            self.layers.append(tcp_info)
            self.protocol = "TCP"
            self.src_port = tcp_info.get("Source_Port")
            self.dst_port = tcp_info.get("Destination_Port")
            flags = tcp_info.get("Flags_Summary", "")
            seq = tcp_info.get("Sequence_Number", 0)
            ack = tcp_info.get("Acknowledgment_Number", 0)
            win = tcp_info.get("Window_Size", 0)
            self.info = f"{self.src_port} -> {self.dst_port} {flags} Seq={seq} Ack={ack} Win={win} Len={len(remaining)}"

            # Layer 7 over TCP: HTTP / TLS
            if self.src_port in (80, 8080) or self.dst_port in (80, 8080):
                http_info = PacketDissector.dissect_http(remaining)
                if http_info:
                    self.layers.append(http_info)
                    self.protocol = "HTTP"
                    self.info = f"{http_info.get('First_Line', 'HTTP')}"

            elif self.src_port == 443 or self.dst_port == 443:
                tls_info = PacketDissector.dissect_tls(remaining)
                if tls_info:
                    self.layers.append(tls_info)
                    self.protocol = "TLS"
                    sni = tls_info.get("Server_Name_Indication_(SNI)", "")
                    self.info = f"{tls_info.get('Handshake_Type', 'TLS Handshake')} {sni}".strip()

        elif l3_proto_code == 17:  # UDP
            udp_info, remaining = PacketDissector.dissect_udp(remaining)
            self.layers.append(udp_info)
            self.protocol = "UDP"
            self.src_port = udp_info.get("Source_Port")
            self.dst_port = udp_info.get("Destination_Port")
            self.info = f"{self.src_port} -> {self.dst_port} Len={len(remaining)}"

            # Layer 7 over UDP: DNS, DHCP, NTP
            if self.src_port == 53 or self.dst_port == 53:
                dns_info = PacketDissector.dissect_dns(remaining)
                self.layers.append(dns_info)
                self.protocol = "DNS"
                queries = ", ".join(dns_info.get("Queries", []))
                mtype = dns_info.get("Message_Type", "DNS")
                self.info = f"Standard {mtype}: {queries}"
            elif self.src_port in (67, 68) or self.dst_port in (67, 68):
                self.protocol = "DHCP"
                self.info = f"DHCP Message (Port {self.src_port} -> {self.dst_port})"
            elif self.src_port == 123 or self.dst_port == 123:
                self.protocol = "NTP"
                self.info = "Network Time Protocol (NTP)"

        if not self.info:
            self.info = f"Length={self.captured_length} bytes"

    def get_hex_dump(self) -> str:
        """Returns standard Hex & ASCII dump representation."""
        return bytes_to_hex_dump(self.raw_data)

    def to_dict(self) -> Dict[str, Any]:
        """Convert packet to serializable dictionary."""
        return {
            "Packet_Number": self.packet_num,
            "Timestamp": datetime.datetime.fromtimestamp(self.timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3],
            "Relative_Time": round(self.rel_time, 6),
            "Source": self.src,
            "Destination": self.dst,
            "Source_Port": self.src_port,
            "Destination_Port": self.dst_port,
            "Protocol": self.protocol,
            "Length": self.captured_length,
            "Info": self.info,
            "Layers": self.layers
        }


class PcapReader:
    """Reads and parses classic PCAP and modern PCAPNG capture files."""

    @classmethod
    def read_file(cls, filepath: str) -> List[ParsedPacket]:
        """Auto-detect format and parse packets."""
        with open(filepath, "rb") as f:
            magic = f.read(4)

        if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4", b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d"):
            return cls._read_classic_pcap(filepath, magic)
        elif magic == b"\x0a\x0d\x0d\x0a":
            return cls._read_pcapng(filepath)
        else:
            raise ValueError(f"Unrecognized PCAP magic header: {magic.hex()}")

    @classmethod
    def _read_classic_pcap(cls, filepath: str, magic: bytes) -> List[ParsedPacket]:
        """Parses standard Libpcap (.pcap) format."""
        packets = []
        is_little_endian = magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1")
        is_nanosecond = magic in (b"\x4d\x3c\xb2\xa1", b"\xa1\xb2\x3c\x4d")
        endian = "<" if is_little_endian else ">"

        with open(filepath, "rb") as f:
            global_header = f.read(24)
            if len(global_header) < 24:
                return []

            packet_num = 1
            first_ts = None

            while True:
                pkt_hdr = f.read(16)
                if len(pkt_hdr) < 16:
                    break

                ts_sec, ts_sub, incl_len, orig_len = struct.unpack(f"{endian}IIII", pkt_hdr)
                sub_factor = 1e9 if is_nanosecond else 1e6
                ts = float(ts_sec) + (float(ts_sub) / sub_factor)

                if first_ts is None:
                    first_ts = ts
                rel_time = ts - first_ts

                pkt_data = f.read(incl_len)
                if len(pkt_data) < incl_len:
                    break

                pkt = ParsedPacket(
                    packet_num=packet_num,
                    timestamp=ts,
                    raw_data=pkt_data,
                    cap_len=incl_len,
                    orig_len=orig_len,
                    rel_time=rel_time
                )
                packets.append(pkt)
                packet_num += 1

        return packets

    @classmethod
    def _read_pcapng(cls, filepath: str) -> List[ParsedPacket]:
        """Parses PCAPNG format blocks (SHB, IDB, EPB, SPB)."""
        packets = []
        packet_num = 1
        first_ts = None
        endian = "<"

        with open(filepath, "rb") as f:
            while True:
                header = f.read(8)
                if len(header) < 8:
                    break

                block_type, block_len = struct.unpack(f"{endian}II", header)

                if block_type == 0x0A0D0D0A:
                    magic = f.read(4)
                    if magic == b"\x1A\x2B\x3C\x4D":
                        endian = ">"
                    else:
                        endian = "<"
                    f.seek(-12, 1)
                    header = f.read(8)
                    block_type, block_len = struct.unpack(f"{endian}II", header)

                block_body_len = block_len - 12
                if block_body_len < 0:
                    break

                body = f.read(block_body_len)
                trailing_len = f.read(4)

                if block_type == 0x00000006:
                    if len(body) >= 20:
                        interface_id, ts_high, ts_low, cap_len, orig_len = struct.unpack(
                            f"{endian}IIIII", body[0:20]
                        )
                        raw_ts = (ts_high << 32) | ts_low
                        ts = raw_ts / 1000000.0

                        if first_ts is None:
                            first_ts = ts
                        rel_time = ts - first_ts

                        pkt_data = body[20:20 + cap_len]
                        pkt = ParsedPacket(
                            packet_num=packet_num,
                            timestamp=ts,
                            raw_data=pkt_data,
                            cap_len=cap_len,
                            orig_len=orig_len,
                            rel_time=rel_time
                        )
                        packets.append(pkt)
                        packet_num += 1

                elif block_type == 0x00000003:
                    if len(body) >= 4:
                        orig_len = struct.unpack(f"{endian}I", body[0:4])[0]
                        pkt_data = body[4:4 + orig_len]
                        ts = datetime.datetime.now().timestamp()
                        pkt = ParsedPacket(
                            packet_num=packet_num,
                            timestamp=ts,
                            raw_data=pkt_data,
                            cap_len=len(pkt_data),
                            orig_len=orig_len,
                            rel_time=0.0
                        )
                        packets.append(pkt)
                        packet_num += 1

        return packets
