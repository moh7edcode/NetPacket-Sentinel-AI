"""
NetPacket Inspector - Incident Response Playbook & AI Forensic Triage Engine
Synthesizes chronological attack timelines, kill-chain phases, and tactical SOC remediation playbooks.
"""

from typing import List, Dict, Any
from threat_detector import ThreatAlert
from pcap_parser import ParsedPacket


class IncidentTriageEngine:
    """Generates chronological attack timelines and automated SOC Incident Response playbooks."""

    @classmethod
    def generate_attack_timeline(cls, alerts: List[ThreatAlert], packets: List[ParsedPacket]) -> List[Dict[str, Any]]:
        """Reconstructs the multi-stage attack lifecycle in chronological order."""
        if not alerts:
            return []

        # Find first packet timestamp for each alert
        pkt_time_map = {p.packet_num: p.rel_time for p in packets}

        timeline_events = []
        for alert in alerts:
            first_pkt = alert.related_packet_nums[0] if alert.related_packet_nums else 1
            rel_t = pkt_time_map.get(first_pkt, 0.0)

            # Map MITRE Tactic to Cyber Kill-Chain Phase
            phase = "Reconnaissance" if "Discovery" in alert.mitre_tactic else (
                "Credential Access" if "Credential" in alert.mitre_tactic else (
                    "Exfiltration" if "Exfiltration" in alert.mitre_tactic else (
                        "Command & Control" if "Command" in alert.mitre_tactic else (
                            "Lateral Movement" if "Collection" in alert.mitre_tactic else "Exploitation / Action"
                        )
                    )
                )
            )

            timeline_events.append({
                "Timestamp_Rel": round(rel_t, 4),
                "Kill_Chain_Phase": phase,
                "Incident_Title": alert.title,
                "Severity": alert.severity,
                "Attacker": alert.source_ip,
                "Victim": alert.target_ip,
                "MITRE_ID": alert.mitre_technique_id,
                "Trigger_Packets": alert.related_packet_nums,
                "Description": alert.description
            })

        timeline_events.sort(key=lambda x: x["Timestamp_Rel"])
        return timeline_events

    @classmethod
    def generate_remediation_playbook(cls, alerts: List[ThreatAlert], ip_profiles: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Produces actionable, step-by-step incident response remediation recommendations."""
        playbook_steps = []
        step_num = 1

        # Check for Compromised / Malicious External IPs to Block
        c2_alerts = [a for a in alerts if "C2" in a.title or "Tunneling" in a.title or "Exfiltration" in a.title]
        if c2_alerts:
            targets_to_block = set()
            for a in c2_alerts:
                if a.target_ip and a.target_ip not in ("DNS Server", "Unknown"):
                    targets_to_block.add(a.target_ip)
                if a.source_ip and "." in a.source_ip and not a.source_ip.startswith("192.168."):
                    targets_to_block.add(a.source_ip)

            if targets_to_block:
                playbook_steps.append({
                    "Step": step_num,
                    "Priority": "URGENT (P0)",
                    "Action": "Perimeter Firewall Egress & Ingress Block",
                    "Target": ", ".join(targets_to_block),
                    "Instructions": f"Immediately blacklist external C2 IP addresses ({', '.join(targets_to_block)}) on all edge firewalls, UTMs, and SIEM drop rules.",
                    "Rationale": "Sever active Command & Control communication and prevent ongoing data exfiltration."
                })
                step_num += 1

        # Check for Leaked Plaintext Credentials
        cred_alerts = [a for a in alerts if "Credential" in a.title or "Leak" in a.title]
        if cred_alerts:
            sample_accounts = []
            for ca in cred_alerts:
                sample_accounts.extend(ca.evidence.get("Exposed_Credentials_Sample", []))

            acc_str = f" (Identified: {', '.join(sample_accounts[:2])})" if sample_accounts else ""
            playbook_steps.append({
                "Step": step_num,
                "Priority": "CRITICAL (P0)",
                "Action": "Forced Password Reset & Session Revocation",
                "Target": "Compromised Accounts",
                "Instructions": f"Trigger immediate password reset and revoke all active Kerberos/OAuth tokens for accounts transmitted in cleartext{acc_str}.",
                "Rationale": "Prevent attacker from using captured credentials for lateral movement or privilege escalation."
            })
            step_num += 1

        # Check for ARP Spoofing / MitM
        arp_alerts = [a for a in alerts if "ARP" in a.title]
        if arp_alerts:
            playbook_steps.append({
                "Step": step_num,
                "Priority": "HIGH (P1)",
                "Action": "Switchport Security & Dynamic ARP Inspection (DAI)",
                "Target": "Local LAN Switch Infrastructure",
                "Instructions": "Enable Dynamic ARP Inspection (DAI) and DHCP Snooping on local managed switches. Flush corrupted ARP caches on default gateway.",
                "Rationale": "Eliminate Man-in-the-Middle eavesdropping on the local network segment."
            })
            step_num += 1

        # Check for Internal Compromised Nodes to Isolate
        malicious_internal = [p["IP"] for p in ip_profiles if p.get("Threat_Level") == "MALICIOUS" and p["IP"].startswith("192.168.")]
        if malicious_internal:
            playbook_steps.append({
                "Step": step_num,
                "Priority": "HIGH (P1)",
                "Action": "Host Isolation & EDR Forensics",
                "Target": ", ".join(malicious_internal),
                "Instructions": f"Isolate internal endpoints ({', '.join(malicious_internal)}) from the local VLAN to prevent malware propagation. Collect memory dump and autorun artifacts.",
                "Rationale": "Contain patient-zero machine and preserve volatile RAM forensics."
            })
            step_num += 1

        # Check for DNS Exfiltration
        dns_alerts = [a for a in alerts if "DNS" in a.title]
        if dns_alerts:
            playbook_steps.append({
                "Step": step_num,
                "Priority": "MEDIUM (P2)",
                "Action": "DNS Sinkholing & Protocol Inspection",
                "Target": "Internal DNS Resolvers",
                "Instructions": "Configure internal DNS resolvers to sinkhole queries matching exfil subdomains and disallow direct outbound UDP 53 traffic from endpoints.",
                "Rationale": "Close DNS covert tunneling vector."
            })
            step_num += 1

        return playbook_steps
