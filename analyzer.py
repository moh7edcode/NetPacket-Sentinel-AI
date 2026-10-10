"""
NetPacket Inspector - Network Traffic Statistics & Security Analytics
Analyzes packet streams for protocol breakdowns, top talkers, conversational streams, and anomalies.
"""

from collections import Counter, defaultdict
from typing import List, Dict, Any
from pcap_parser import ParsedPacket


class TrafficAnalyzer:
    """Calculates comprehensive network statistics and security insights from parsed packets."""

    def __init__(self, packets: List[ParsedPacket]):
        self.packets = packets

    def get_summary_statistics(self) -> Dict[str, Any]:
        """Calculates general capture statistics."""
        if not self.packets:
            return {
                "Total_Packets": 0,
                "Total_Bytes": 0,
                "Duration_Seconds": 0.0,
                "Avg_Packet_Size": 0,
                "Packet_Rate": 0.0,
                "Data_Rate_Kbps": 0.0
            }

        total_pkts = len(self.packets)
        total_bytes = sum(p.captured_length for p in self.packets)
        first_time = self.packets[0].timestamp
        last_time = self.packets[-1].timestamp
        duration = max(0.0001, last_time - first_time)

        avg_size = total_bytes / total_pkts if total_pkts > 0 else 0
        pkt_rate = total_pkts / duration
        kbps = (total_bytes * 8) / (duration * 1000.0)

        return {
            "Total_Packets": total_pkts,
            "Total_Bytes": total_bytes,
            "Total_Bytes_Formatted": self._format_bytes(total_bytes),
            "Duration_Seconds": round(duration, 4),
            "Avg_Packet_Size": f"{avg_size:.1f} bytes",
            "Packet_Rate": f"{pkt_rate:.2f} pkts/s",
            "Data_Rate_Kbps": f"{kbps:.2f} Kbps"
        }

    def get_protocol_distribution(self) -> List[Dict[str, Any]]:
        """Returns protocol counts and percentages."""
        if not self.packets:
            return []

        counts = Counter(p.protocol for p in self.packets)
        total = len(self.packets)

        distribution = []
        for proto, cnt in counts.most_common():
            distribution.append({
                "Protocol": proto,
                "Count": cnt,
                "Percentage": round((cnt / total) * 100, 2)
            })
        return distribution

    def get_top_talkers(self, limit: int = 10) -> Dict[str, List[Dict[str, Any]]]:
        """Returns top source IPs, top destination IPs, and top IP conversations."""
        src_counter = Counter()
        dst_counter = Counter()
        conv_counter = Counter()

        src_bytes = Counter()
        dst_bytes = Counter()

        for p in self.packets:
            if p.src and p.src != "Unknown":
                src_counter[p.src] += 1
                src_bytes[p.src] += p.captured_length
            if p.dst and p.dst != "Unknown":
                dst_counter[p.dst] += 1
                dst_bytes[p.dst] += p.captured_length

            # IP conversation pair
            if p.src and p.dst and p.src != "Unknown" and p.dst != "Unknown":
                pair = tuple(sorted([p.src, p.dst]))
                conv_counter[pair] += 1

        top_src = [
            {"IP": ip, "Packets": cnt, "Bytes": self._format_bytes(src_bytes[ip])}
            for ip, cnt in src_counter.most_common(limit)
        ]
        top_dst = [
            {"IP": ip, "Packets": cnt, "Bytes": self._format_bytes(dst_bytes[ip])}
            for ip, cnt in dst_counter.most_common(limit)
        ]
        top_conv = [
            {"Node_A": pair[0], "Node_B": pair[1], "Packets": cnt}
            for pair, cnt in conv_counter.most_common(limit)
        ]

        return {
            "Top_Sources": top_src,
            "Top_Destinations": top_dst,
            "Top_Conversations": top_conv
        }

    def get_top_ports(self, limit: int = 10) -> List[Dict[str, Any]]:
        """Returns most active TCP/UDP ports and service mapping."""
        port_names = {
            20: "FTP-Data", 21: "FTP-Control", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 80: "HTTP", 110: "POP3",
            123: "NTP", 143: "IMAP", 443: "HTTPS/TLS", 445: "SMB", 993: "IMAPS",
            995: "POP3S", 1900: "SSDP", 3306: "MySQL", 3389: "RDP", 5353: "mDNS",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }

        port_counts = Counter()
        for p in self.packets:
            if p.src_port:
                port_counts[p.src_port] += 1
            if p.dst_port:
                port_counts[p.dst_port] += 1

        results = []
        for port, cnt in port_counts.most_common(limit):
            service = port_names.get(port, "Dynamic / Unknown")
            results.append({
                "Port": port,
                "Service": service,
                "Occurrences": cnt
            })
        return results

    def get_security_insights(self) -> List[Dict[str, str]]:
        """Detects notable network activity patterns and potential security issues."""
        insights = []

        # 1. Plaintext HTTP Traffic
        http_pkts = [p for p in self.packets if p.protocol == "HTTP"]
        if http_pkts:
            insights.append({
                "Severity": "INFO / WARNING",
                "Category": "Unencrypted HTTP",
                "Description": f"Detected {len(http_pkts)} unencrypted HTTP packets. Sensitive data or credentials might be in plaintext."
            })

        # 2. DNS Queries Summary
        dns_queries = set()
        for p in self.packets:
            if p.protocol == "DNS":
                for layer in p.layers:
                    if layer.get("LayerName") == "Domain Name System (DNS)":
                        for q in layer.get("Queries", []):
                            if q != "(None)":
                                dns_queries.add(q)
        if dns_queries:
            insights.append({
                "Severity": "INFO",
                "Category": "DNS Activity",
                "Description": f"Resolved {len(dns_queries)} unique domain queries (e.g. {list(dns_queries)[:3]})."
            })

        # 3. High Volume TCP SYN (Potential Scan)
        syn_only = 0
        for p in self.packets:
            if p.protocol == "TCP":
                for layer in p.layers:
                    flags = layer.get("Flags_Detail", {})
                    if flags.get("SYN") and not flags.get("ACK"):
                        syn_only += 1

        if syn_only > 20:
            insights.append({
                "Severity": "WARNING",
                "Category": "Potential Port Scan",
                "Description": f"High volume of isolated TCP SYN packets ({syn_only} packets). Possible port scanning or connection probes."
            })

        # 4. ARP Broadcast volume
        arp_count = sum(1 for p in self.packets if p.protocol == "ARP")
        if arp_count > 50:
            insights.append({
                "Severity": "INFO",
                "Category": "High ARP Traffic",
                "Description": f"Identified {arp_count} ARP broadcast/reply packets on the local subnet."
            })

        if not insights:
            insights.append({
                "Severity": "NORMAL",
                "Category": "Traffic Baseline",
                "Description": "No immediate anomalies or unencrypted alerts flagged in this capture."
            })

        return insights

    @staticmethod
    def _format_bytes(num_bytes: int) -> str:
        """Format raw byte counts to human readable KB/MB/GB."""
        if num_bytes < 1024:
            return f"{num_bytes} B"
        elif num_bytes < 1024 * 1024:
            return f"{num_bytes / 1024.0:.2f} KB"
        elif num_bytes < 1024 * 1024 * 1024:
            return f"{num_bytes / (1024.0 * 1024.0):.2f} MB"
        else:
            return f"{num_bytes / (1024.0 * 1024.0 * 1024.0):.2f} GB"
