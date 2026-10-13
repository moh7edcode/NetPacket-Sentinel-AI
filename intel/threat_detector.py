"""
NetPacket Inspector - Threat Detector & NIDS Rule Engine
Detects network reconnaissance scans, DNS tunneling, ARP spoofing, cleartext credential leaks, and DoS attacks.
"""

from collections import defaultdict, Counter
from typing import List, Dict, Any, Set
from core.pcap_parser import ParsedPacket
from core.payload_decoder import PayloadDecoder
import base64
import re


class ThreatAlert:
    """Represents an identified security incident or malicious pattern."""

    def __init__(
        self,
        rule_id: str,
        title: str,
        severity: str,  # "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"
        mitre_tactic: str,
        mitre_technique_id: str,
        description: str,
        source_ip: str,
        target_ip: str,
        related_packet_nums: List[int],
        evidence: Dict[str, Any] = None
    ):
        self.rule_id = rule_id
        self.title = title
        self.severity = severity
        self.mitre_tactic = mitre_tactic
        self.mitre_technique_id = mitre_technique_id
        self.description = description
        self.source_ip = source_ip
        self.target_ip = target_ip
        self.related_packet_nums = related_packet_nums
        self.evidence = evidence or {}

    def to_dict(self) -> Dict[str, Any]:
        return {
            "Rule_ID": self.rule_id,
            "Title": self.title,
            "Severity": self.severity,
            "MITRE_Tactic": self.mitre_tactic,
            "MITRE_ID": self.mitre_technique_id,
            "Description": self.description,
            "Source_IP": self.source_ip,
            "Target_IP": self.target_ip,
            "Packet_Count": len(self.related_packet_nums),
            "Packet_Numbers": self.related_packet_nums,
            "Evidence": self.evidence
        }


class ThreatDetector:
    """Automated Network Forensics & Behavioral Threat Detection Engine."""

    def __init__(self, packets: List[ParsedPacket]):
        self.packets = packets
        self.alerts: List[ThreatAlert] = []

    def run_all_checks(self) -> List[ThreatAlert]:
        """Execute all forensic detection modules."""
        self.alerts.clear()

        self._check_dns_tunneling_and_exfiltration()
        self._check_tcp_port_scans()
        self._check_stealth_tcp_scans()
        self._check_icmp_ping_sweeps()
        self._check_arp_spoofing()
        self._check_plaintext_credentials_and_leaks()
        self._check_syn_and_icmp_floods()
        self._check_suspicious_backdoor_ports()

        # Sort alerts by severity (CRITICAL -> HIGH -> MEDIUM -> LOW -> INFO)
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.alerts.sort(key=lambda a: sev_order.get(a.severity, 5))
        return self.alerts

    def _check_dns_tunneling_and_exfiltration(self):
        """Detects DNS Tunneling / Exfiltration (High entropy subdomains, long domain lengths, base64 payload inside queries)."""
        dns_packets = [p for p in self.packets if p.protocol == "DNS"]
        if not dns_packets:
            return

        suspicious_queries = []
        domain_query_count = Counter()
        src_dns_pkts = defaultdict(list)

        for p in dns_packets:
            src_dns_pkts[p.src].append(p.packet_num)
            for layer in p.layers:
                if layer.get("LayerName") == "Domain Name System (DNS)":
                    for query in layer.get("Queries", []):
                        domain = query.split(" ")[0].strip(".")
                        if not domain or domain == "(None)":
                            continue

                        domain_query_count[domain] += 1
                        subdomain_parts = domain.split(".")
                        longest_label = max(subdomain_parts, key=len) if subdomain_parts else ""

                        # Check if subdomain has characteristics of exfiltration (length > 25, high entropy or base64)
                        if len(longest_label) >= 20:
                            entropy = PayloadDecoder.calculate_entropy(longest_label.encode())
                            # Try base64 detection
                            decoded_text = ""
                            try:
                                decoded_bytes = base64.b64decode(longest_label + "==", validate=False)
                                if sum(1 for b in decoded_bytes if 32 <= b <= 126) > len(decoded_bytes) * 0.5:
                                    decoded_text = decoded_bytes.decode("latin-1", errors="ignore")
                            except Exception:
                                pass

                            if entropy > 3.4 or len(longest_label) > 35 or decoded_text:
                                suspicious_queries.append({
                                    "Packet_Num": p.packet_num,
                                    "Source_IP": p.src,
                                    "Domain": domain,
                                    "Label_Length": len(longest_label),
                                    "Entropy": entropy,
                                    "Decoded_Exfiltrated_Data": decoded_text
                                })

        if suspicious_queries:
            pkt_nums = [item["Packet_Num"] for item in suspicious_queries]
            first_src = suspicious_queries[0]["Source_IP"]
            sample_domains = [item["Domain"] for item in suspicious_queries[:3]]
            sample_decoded = [item["Decoded_Exfiltrated_Data"] for item in suspicious_queries if item["Decoded_Exfiltrated_Data"]]

            evidence = {
                "Sample_Domains": sample_domains,
                "Suspicious_Queries_Count": len(suspicious_queries)
            }
            if sample_decoded:
                evidence["Decoded_Data_Sample"] = sample_decoded[:2]

            self.alerts.append(ThreatAlert(
                rule_id="NIDS-EXFIL-001",
                title="DNS Tunneling / Data Exfiltration Detected",
                severity="CRITICAL",
                mitre_tactic="Exfiltration / Command & Control",
                mitre_technique_id="T1048.003 / T1071.004",
                description=f"Identified {len(suspicious_queries)} anomalous DNS queries with encoded/high-entropy subdomains indicative of covert channel exfiltration.",
                source_ip=first_src,
                target_ip="DNS Server",
                related_packet_nums=pkt_nums,
                evidence=evidence
            ))

    def _check_tcp_port_scans(self):
        """Detects TCP SYN Port Scans (T1046) - Single source targeting multiple ports."""
        syn_by_src = defaultdict(lambda: {"dst_ports": set(), "packets": [], "targets": set()})

        for p in self.packets:
            if p.protocol == "TCP":
                for layer in p.layers:
                    if layer.get("LayerName") == "Transmission Control Protocol (TCP)":
                        flags = layer.get("Flags_Detail", {})
                        if flags.get("SYN") and not flags.get("ACK"):
                            syn_by_src[p.src]["dst_ports"].add(p.dst_port)
                            syn_by_src[p.src]["targets"].add(p.dst)
                            syn_by_src[p.src]["packets"].append(p.packet_num)

        for src, data in syn_by_src.items():
            if len(data["dst_ports"]) >= 4 or (len(data["packets"]) >= 10 and len(data["dst_ports"]) >= 2):
                target_ip = list(data["targets"])[0] if len(data["targets"]) == 1 else f"{len(data['targets'])} Target Hosts"
                self.alerts.append(ThreatAlert(
                    rule_id="NIDS-SCAN-001",
                    title="TCP SYN Port Scan Activity",
                    severity="HIGH",
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1046 (Network Service Scanning)",
                    description=f"Host {src} probed {len(data['dst_ports'])} unique TCP ports across {len(data['targets'])} destination(s) using half-open SYN packets.",
                    source_ip=src,
                    target_ip=target_ip,
                    related_packet_nums=data["packets"][:50],
                    evidence={"Probed_Ports": sorted(list(data["dst_ports"]))[:10], "Total_SYN_Packets": len(data["packets"])}
                ))

    def _check_stealth_tcp_scans(self):
        """Detects TCP FIN, NULL, or Xmas Stealth Scans."""
        stealth_pkts = []
        for p in self.packets:
            if p.protocol == "TCP":
                for layer in p.layers:
                    if layer.get("LayerName") == "Transmission Control Protocol (TCP)":
                        flags = layer.get("Flags_Detail", {})
                        is_null = not any(flags.values())
                        is_fin_only = flags.get("FIN") and not any([flags.get("SYN"), flags.get("ACK"), flags.get("RST")])
                        is_xmas = flags.get("FIN") and flags.get("PSH") and flags.get("URG")

                        if is_null or is_fin_only or is_xmas:
                            scan_type = "Xmas Scan" if is_xmas else ("NULL Scan" if is_null else "FIN Scan")
                            stealth_pkts.append((p, scan_type))

        if stealth_pkts:
            pkt_nums = [item[0].packet_num for item in stealth_pkts]
            scan_types = list(set(item[1] for item in stealth_pkts))
            first_p = stealth_pkts[0][0]
            self.alerts.append(ThreatAlert(
                rule_id="NIDS-SCAN-002",
                title=f"TCP Stealth Scan Detected ({', '.join(scan_types)})",
                severity="HIGH",
                mitre_tactic="Discovery / Defense Evasion",
                mitre_technique_id="T1046 / T1562",
                description=f"Detected {len(stealth_pkts)} abnormal TCP packets matching stealth reconnaissance signatures ({', '.join(scan_types)}).",
                source_ip=first_p.src,
                target_ip=first_p.dst,
                related_packet_nums=pkt_nums,
                evidence={"Scan_Types": scan_types, "Packet_Count": len(stealth_pkts)}
            ))

    def _check_icmp_ping_sweeps(self):
        """Detects ICMP Echo Ping Sweeps across multiple destination hosts."""
        icmp_by_src = defaultdict(lambda: {"targets": set(), "packets": []})

        for p in self.packets:
            if p.protocol == "ICMP":
                for layer in p.layers:
                    if layer.get("Type_Code_Val") == 8:  # Echo Request
                        icmp_by_src[p.src]["targets"].add(p.dst)
                        icmp_by_src[p.src]["packets"].append(p.packet_num)

        for src, data in icmp_by_src.items():
            if len(data["targets"]) >= 4 or len(data["packets"]) >= 15:
                self.alerts.append(ThreatAlert(
                    rule_id="NIDS-DISC-001",
                    title="ICMP Network Ping Sweep / Reconnaissance",
                    severity="MEDIUM",
                    mitre_tactic="Discovery",
                    mitre_technique_id="T1018 (Remote System Discovery)",
                    description=f"Host {src} sent ICMP Echo probes to {len(data['targets'])} separate network hosts.",
                    source_ip=src,
                    target_ip=f"{len(data['targets'])} Destination Hosts",
                    related_packet_nums=data["packets"][:30],
                    evidence={"Targets_Count": len(data["targets"]), "Total_Echo_Requests": len(data["packets"])}
                ))

    def _check_arp_spoofing(self):
        """Detects ARP Spoofing / Poisoning (Same IP with multiple distinct MAC addresses)."""
        ip_mac_map = defaultdict(set)
        arp_pkts = []

        for p in self.packets:
            if p.protocol == "ARP":
                for layer in p.layers:
                    if layer.get("LayerName") == "Address Resolution Protocol (ARP)":
                        sender_ip = layer.get("Sender_IP")
                        sender_mac = layer.get("Sender_MAC")
                        if sender_ip and sender_mac:
                            ip_mac_map[sender_ip].add(sender_mac)
                            arp_pkts.append(p.packet_num)

        for ip, macs in ip_mac_map.items():
            if len(macs) > 1:
                self.alerts.append(ThreatAlert(
                    rule_id="NIDS-MITM-001",
                    title="ARP Poisoning / Man-in-the-Middle (MitM) Attempt",
                    severity="CRITICAL",
                    mitre_tactic="Credential Access / Collection",
                    mitre_technique_id="T1557.002 (ARP Poisoning)",
                    description=f"IP {ip} is claimed by multiple conflicting MAC addresses ({', '.join(macs)}), indicating an active ARP spoofing attack.",
                    source_ip=", ".join(macs),
                    target_ip=ip,
                    related_packet_nums=arp_pkts,
                    evidence={"Conflicting_MACs": list(macs), "Target_IP": ip}
                ))

    def _check_plaintext_credentials_and_leaks(self):
        """Detects Plaintext Credentials (HTTP Basic Auth, POST password fields, FTP/Telnet logins)."""
        leak_pkts = []
        for p in self.packets:
            raw_text = p.raw_data.decode("latin-1", errors="ignore")

            # 1. HTTP Basic Authorization: Basic <base64>
            auth_match = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", raw_text, re.IGNORECASE)
            if auth_match:
                b64_cred = auth_match.group(1)
                try:
                    decoded_cred = base64.b64decode(b64_cred).decode("utf-8", errors="replace")
                    leak_pkts.append({
                        "Packet": p,
                        "Type": "HTTP Basic Auth",
                        "Credentials": decoded_cred,
                        "Raw": auth_match.group(0)
                    })
                except Exception:
                    pass

            # 2. HTTP POST Form containing passwords
            if "POST " in raw_text and ("password=" in raw_text.lower() or "passwd=" in raw_text.lower() or "pwd=" in raw_text.lower()):
                leak_pkts.append({
                    "Packet": p,
                    "Type": "HTTP POST Plaintext Password",
                    "Credentials": "(Cleartext Form Data Detected)",
                    "Raw": "POST Body with credentials"
                })

            # 3. FTP / Telnet Plaintext Login
            if p.src_port == 21 or p.dst_port == 21:
                ftp_match = re.search(r"(USER|PASS)\s+([^\r\n]+)", raw_text)
                if ftp_match:
                    leak_pkts.append({
                        "Packet": p,
                        "Type": f"FTP {ftp_match.group(1)} Leak",
                        "Credentials": ftp_match.group(0),
                        "Raw": ftp_match.group(0)
                    })

        if leak_pkts:
            pkt_nums = [item["Packet"].packet_num for item in leak_pkts]
            sample_types = [item["Type"] for item in leak_pkts]
            sample_creds = [item["Credentials"] for item in leak_pkts if item["Credentials"] != "(Cleartext Form Data Detected)"]
            first_p = leak_pkts[0]["Packet"]

            self.alerts.append(ThreatAlert(
                rule_id="NIDS-CRED-001",
                title="Cleartext Credential Leak & Exfiltration",
                severity="HIGH",
                mitre_tactic="Credential Access",
                mitre_technique_id="T1040 (Network Sniffing) / T1552",
                description=f"Identified {len(leak_pkts)} packet(s) transmitting sensitive authentication credentials in unencrypted plaintext ({', '.join(set(sample_types))}).",
                source_ip=first_p.src,
                target_ip=first_p.dst,
                related_packet_nums=pkt_nums,
                evidence={"Credential_Types": list(set(sample_types)), "Exposed_Credentials_Sample": sample_creds[:3]}
            ))

    def _check_syn_and_icmp_floods(self):
        """Detects High Volume Denial-of-Service Flood bursts."""
        # Check SYN packets per destination
        syn_counts = Counter()
        syn_pkts = defaultdict(list)
        for p in self.packets:
            if p.protocol == "TCP":
                for layer in p.layers:
                    if layer.get("LayerName") == "Transmission Control Protocol (TCP)":
                        flags = layer.get("Flags_Detail", {})
                        if flags.get("SYN") and not flags.get("ACK"):
                            syn_counts[p.dst] += 1
                            syn_pkts[p.dst].append(p.packet_num)

        for target_ip, count in syn_counts.items():
            if count >= 30:
                self.alerts.append(ThreatAlert(
                    rule_id="NIDS-DOS-001",
                    title="Potential TCP SYN Flood (DoS)",
                    severity="HIGH",
                    mitre_tactic="Impact",
                    mitre_technique_id="T1498 (Network Denial of Service)",
                    description=f"Target {target_ip} received a burst of {count} TCP SYN packets with minimal completions.",
                    source_ip="Multiple / Distributed Sources",
                    target_ip=target_ip,
                    related_packet_nums=syn_pkts[target_ip][:50],
                    evidence={"SYN_Count": count}
                ))

    def _check_suspicious_backdoor_ports(self):
        """Detects Connections to Known Backdoor, C2, and Trojan Ports."""
        known_bad_ports = {
            4444: "Metasploit Default Listener / Reverse Shell",
            1337: "Common Hacker / Backdoor Shell Port",
            31337: "Back Orifice Trojan",
            6667: "IRC Botnet C2 Channel",
            9001: "Tor / Alternative C2 Port",
            5555: "Android ADB Remote Exploit / C2"
        }

        suspicious_hits = []
        for p in self.packets:
            port = p.dst_port or p.src_port
            if port in known_bad_ports:
                suspicious_hits.append((p, port, known_bad_ports[port]))

        if suspicious_hits:
            pkt_nums = [h[0].packet_num for h in suspicious_hits]
            descs = list(set(f"Port {h[1]} ({h[2]})" for h in suspicious_hits))
            first_p = suspicious_hits[0][0]
            self.alerts.append(ThreatAlert(
                rule_id="NIDS-C2-001",
                title="Suspicious Backdoor / C2 Port Activity",
                severity="MEDIUM",
                mitre_tactic="Command and Control",
                mitre_technique_id="T1571 (Non-Standard Port)",
                description=f"Detected communication matching known malicious backdoor / C2 signatures ({', '.join(descs)}).",
                source_ip=first_p.src,
                target_ip=first_p.dst,
                related_packet_nums=pkt_nums,
                evidence={"Matched_Services": descs}
            ))
