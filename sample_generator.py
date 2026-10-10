"""
NetPacket Inspector - Sample PCAP Generator
Generates realistic multi-protocol PCAP captures for testing without external tools.
"""

import struct
import time
from typing import List


def generate_sample_pcap(filepath: str):
    """Generates a valid libpcap file with diverse sample packets."""
    # PCAP Global Header: magic (0xa1b2c3d4), v2.4, tz 0, sig 0, snaplen 65535, linktype 1 (Ethernet)
    global_hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)

    packets_data: List[bytes] = []

    # 1. ARP Request: Who has 192.168.1.1? Tell 192.168.1.50
    eth_arp = bytes.fromhex("ffffffffffff") + bytes.fromhex("001122334455") + struct.pack("!H", 0x0806)
    arp_req = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + bytes.fromhex("001122334455") + \
              bytes([192, 168, 1, 50]) + bytes.fromhex("000000000000") + bytes([192, 168, 1, 1])
    packets_data.append(eth_arp + arp_req)

    # 2. ARP Reply: 192.168.1.1 is at 00:aa:bb:cc:dd:ee
    eth_arp_rep = bytes.fromhex("001122334455") + bytes.fromhex("00aabbccddee") + struct.pack("!H", 0x0806)
    arp_rep = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + bytes.fromhex("00aabbccddee") + \
              bytes([192, 168, 1, 1]) + bytes.fromhex("001122334455") + bytes([192, 168, 1, 50])
    packets_data.append(eth_arp_rep + arp_rep)

    # 3. DNS Query for "google.com" (UDP 53)
    eth_ip = bytes.fromhex("00aabbccddee") + bytes.fromhex("001122334455") + struct.pack("!H", 0x0800)
    # IPv4 Header
    ip_hdr_dns = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 8 + 28, 0x1234, 0x4000, 64, 17, 0) + \
                 bytes([192, 168, 1, 50]) + bytes([8, 8, 8, 8])
    # UDP Header: SrcPort=54321, DstPort=53, Len=28+8, Csum=0
    udp_dns = struct.pack("!HHHH", 54321, 53, 36, 0)
    # DNS Question: google.com (Type A)
    dns_payload = struct.pack("!HHHHHH", 0xABCD, 0x0100, 1, 0, 0, 0) + \
                  b"\x06google\x03com\x00" + struct.pack("!HH", 1, 1)
    packets_data.append(eth_ip + ip_hdr_dns + udp_dns + dns_payload)

    # 4. ICMP Echo (Ping) Request (192.168.1.50 -> 1.1.1.1)
    ip_hdr_icmp = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 8 + 32, 0x1235, 0x4000, 64, 1, 0) + \
                  bytes([192, 168, 1, 50]) + bytes([1, 1, 1, 1])
    icmp_req = struct.pack("!BBHI", 8, 0, 0, 0x00010001) + b"abcdefghijklmnopqrstuvwabcdefghi"
    packets_data.append(eth_ip + ip_hdr_icmp + icmp_req)

    # 5. ICMP Echo (Ping) Reply (1.1.1.1 -> 192.168.1.50)
    eth_ip_rev = bytes.fromhex("001122334455") + bytes.fromhex("00aabbccddee") + struct.pack("!H", 0x0800)
    ip_hdr_icmp_rep = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 8 + 32, 0x5678, 0x4000, 56, 1, 0) + \
                      bytes([1, 1, 1, 1]) + bytes([192, 168, 1, 50])
    icmp_rep = struct.pack("!BBHI", 0, 0, 0, 0x00010001) + b"abcdefghijklmnopqrstuvwabcdefghi"
    packets_data.append(eth_ip_rev + ip_hdr_icmp_rep + icmp_rep)

    # 6. TCP SYN: 192.168.1.50:49200 -> 93.184.216.34:80 (example.com)
    ip_hdr_tcp1 = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0x1236, 0x4000, 64, 6, 0) + \
                  bytes([192, 168, 1, 50]) + bytes([93, 184, 216, 34])
    tcp_syn = struct.pack("!HHIIHHHH", 49200, 80, 1000000, 0, (5 << 12) | 0x0002, 65535, 0, 0)
    packets_data.append(eth_ip + ip_hdr_tcp1 + tcp_syn)

    # 7. TCP SYN-ACK: 93.184.216.34:80 -> 192.168.1.50:49200
    ip_hdr_tcp2 = struct.pack("!BBHHHBBH", 0x45, 0, 40, 0x9999, 0x4000, 54, 6, 0) + \
                  bytes([93, 184, 216, 34]) + bytes([192, 168, 1, 50])
    tcp_synack = struct.pack("!HHIIHHHH", 80, 49200, 5000000, 1000001, (5 << 12) | 0x0012, 65535, 0, 0)
    packets_data.append(eth_ip_rev + ip_hdr_tcp2 + tcp_synack)

    # 8. TCP ACK: 192.168.1.50:49200 -> 93.184.216.34:80
    tcp_ack = struct.pack("!HHIIHHHH", 49200, 80, 1000001, 5000001, (5 << 12) | 0x0010, 65535, 0, 0)
    packets_data.append(eth_ip + ip_hdr_tcp1 + tcp_ack)

    # 9. HTTP GET Request: GET /index.html HTTP/1.1
    http_payload = b"GET /index.html HTTP/1.1\r\nHost: example.com\r\nUser-Agent: NetPacketInspector/1.0\r\nAccept: */*\r\n\r\n"
    ip_hdr_http = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 20 + len(http_payload), 0x1237, 0x4000, 64, 6, 0) + \
                  bytes([192, 168, 1, 50]) + bytes([93, 184, 216, 34])
    tcp_http_req = struct.pack("!HHIIHHHH", 49200, 80, 1000001, 5000001, (5 << 12) | 0x0018, 65535, 0, 0)
    packets_data.append(eth_ip + ip_hdr_http + tcp_http_req + http_payload)

    # 10. HTTP 200 OK Response
    http_response = b"HTTP/1.1 200 OK\r\nServer: Apache/2.4\r\nContent-Type: text/html\r\nContent-Length: 48\r\n\r\n<html><body><h1>PCAP Analysis Success</h1></body></html>"
    ip_hdr_http_resp = struct.pack("!BBHHHBBH", 0x45, 0, 20 + 20 + len(http_response), 0x999A, 0x4000, 54, 6, 0) + \
                       bytes([93, 184, 216, 34]) + bytes([192, 168, 1, 50])
    tcp_http_resp = struct.pack("!HHIIHHHH", 80, 49200, 5000001, 1000001 + len(http_payload), (5 << 12) | 0x0018, 65535, 0, 0)
    packets_data.append(eth_ip_rev + ip_hdr_http_resp + tcp_http_resp + http_response)

    # Write PCAP file
    base_time = time.time() - 60
    with open(filepath, "wb") as f:
        f.write(global_hdr)
        for i, pkt in enumerate(packets_data):
            ts_sec = int(base_time + (i * 0.25))
            ts_usec = int((i * 250000) % 1000000)
            pkt_hdr = struct.pack("<IIII", ts_sec, ts_usec, len(pkt), len(pkt))
            f.write(pkt_hdr)
            f.write(pkt)

    print(f"[+] Successfully generated sample PCAP file with {len(packets_data)} packets: {filepath}")


if __name__ == "__main__":
    generate_sample_pcap("sample_traffic.pcap")
