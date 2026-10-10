"""
NetPacket Inspector Pro - Main Execution Entry Point
Supports Interactive GUI, CLI Forensics, Live SOC Dashboard, and Automated Reporting.
"""

import sys
import os
import argparse
import webbrowser

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

from pcap_parser import PcapReader
from analyzer import TrafficAnalyzer
from threat_detector import ThreatDetector
from stream_profiler import StreamProfiler
from threat_intel import ThreatIntelEngine
from exporter import PacketExporter
from dashboard_generator import DashboardGenerator
from enhanced_sample_generator import generate_enhanced_malicious_sample


def print_cli_summary(filepath: str, vt_api_key: str = None, export_path: str = None, open_dashboard: bool = False):
    """Parses and prints a comprehensive forensic report to CLI and exports requested formats."""
    print("\n" + "=" * 70)
    print(f"⚡ NetPacket Inspector - Threat Forensics: {os.path.basename(filepath)}")
    print("=" * 70 + "\n")

    packets = PcapReader.read_file(filepath)
    print(f"[+] Loaded {len(packets)} packets successfully.\n")

    # 1. Traffic Metrics
    analyzer = TrafficAnalyzer(packets)
    stats = analyzer.get_summary_statistics()
    print("--- [1] GENERAL NETWORK METRICS ---")
    print(f"  • Total Packets  : {stats['Total_Packets']}")
    print(f"  • Total Volume   : {stats['Total_Bytes_Formatted']}")
    print(f"  • Duration       : {stats['Duration_Seconds']} seconds")
    print(f"  • Transfer Rate  : {stats.get('Packet_Rate', 'N/A')} ({stats.get('Data_Rate_Kbps', 'N/A')})\n")

    # 2. Threat Forensics
    td = ThreatDetector(packets)
    alerts = td.run_all_checks()
    print(f"--- [2] 🛡️ IDENTIFIED MALICIOUS ATTACKS & INCIDENTS (MITRE ATT&CK) ---")
    if not alerts:
        print("  ✅ Clean - No active hostile attack signatures identified.")
    else:
        for idx, alert in enumerate(alerts, 1):
            print(f"  [{idx}] [{alert.severity}] {alert.title}")
            print(f"      • MITRE ID    : {alert.mitre_technique_id} ({alert.mitre_tactic})")
            print(f"      • Flow        : {alert.source_ip} -> {alert.target_ip}")
            print(f"      • Trigger Pkts: {alert.related_packet_nums[:8]}")
            print(f"      • Description : {alert.description}")
            for k, v in alert.evidence.items():
                print(f"      • {k} : {v}")
            print()

    # 3. Stream & IP Profiles
    profiler = StreamProfiler(packets, alerts)
    profiles = profiler.get_all_ip_profiles()
    print("--- [3] 🌐 ENDPOINT IP PROFILE & THREAT MATRIX ---")
    print(f"  {'IP Address':<18} {'Threat Level':<14} {'Score':<7} {'Packets':<9} {'Bytes':<10} {'Protocols'}")
    print("  " + "-" * 75)
    for p in profiles[:8]:
        proto_str = ", ".join(f"{k}({v})" for k, v in p["Protocols"].items())
        print(f"  {p['IP']:<18} {p['Threat_Level']:<14} {p['Threat_Score']:<7} {p['Total_Packets']:<9} {p['Total_Bytes']:<10} {proto_str}")
    print()

    # 4. Threat Intel Lookups
    intel = ThreatIntelEngine(vt_api_key)
    iocs = intel.extract_iocs_from_packets(packets)
    print("--- [4] 🦠 VIRUSTOTAL & THREAT INTEL REPUTATION ---")
    for ip in iocs.get("Public_IPs", []):
        r = intel.lookup_ip_deep(ip)
        print(f"  • [IP] {ip:<18} : Verdict = {r.get('Verdict'):<10} | Detections = {r.get('Detections')} | Category = {r.get('Category')}")
    for dom in iocs.get("Domains", []):
        r = intel.lookup_domain_deep(dom)
        print(f"  • [DOM] {dom:<18} : Verdict = {r.get('Verdict'):<10} | Detections = {r.get('Detections')} | Category = {r.get('Category')}")
    print()

    # 5. Export
    if export_path:
        if export_path.endswith(".html"):
            PacketExporter.export_html_report(packets, export_path, os.path.basename(filepath), vt_api_key=vt_api_key)
        elif export_path.endswith(".json"):
            PacketExporter.export_json(packets, export_path, alerts)
        elif export_path.endswith(".csv"):
            PacketExporter.export_csv(packets, export_path)
        print(f"[+] Exported Executive Forensic Report to: {export_path}\n")

    if open_dashboard:
        dash_file = "dashboard.html"
        DashboardGenerator.generate_dashboard(packets, dash_file, os.path.basename(filepath), vt_api_key=vt_api_key)
        print(f"[+] Generated Futuristic SOC Dashboard: {os.path.abspath(dash_file)}")
        webbrowser.open(f"file://{os.path.abspath(dash_file)}")


def main():
    parser = argparse.ArgumentParser(
        description="⚡ NetPacket Inspector Pro - Advanced Cyber Forensics & Threat Analysis Engine"
    )
    parser.add_argument("--file", "-f", help="Path to .pcap or .pcapng packet capture file.")
    parser.add_argument("--cli", action="store_true", help="Run in CLI forensic inspection mode.")
    parser.add_argument("--export", "-e", help="Export path for forensic report (.html, .json, .csv).")
    parser.add_argument("--dashboard", "-d", action="store_true", help="Generate and open the futuristic live SOC Dashboard in web browser.")
    parser.add_argument("--vt-key", help="VirusTotal API v3 key for real-time IoC reputation.")
    parser.add_argument("--sample", action="store_true", help="Generate a rich multi-vector attack PCAP sample and inspect it.")

    args = parser.parse_args()

    if args.sample:
        sample_path = "forensic_attack_sample.pcap"
        generate_enhanced_malicious_sample(sample_path)
        print(f"[+] Multi-vector attack sample capture generated at: {sample_path}")
        from app_gui import launch_gui
        launch_gui(sample_path)
        return

    if args.cli:
        if not args.file:
            print("[-] Error: --file argument is required in CLI mode.")
            sys.exit(1)
        print_cli_summary(args.file, vt_api_key=args.vt_key, export_path=args.export, open_dashboard=args.dashboard)
        return

    if args.dashboard:
        if not args.file:
            print("[-] Error: --file argument is required to generate Dashboard.")
            sys.exit(1)
        packets = PcapReader.read_file(args.file)
        dash_file = "dashboard.html"
        DashboardGenerator.generate_dashboard(packets, dash_file, os.path.basename(args.file), vt_api_key=args.vt_key)
        print(f"[+] Generated Futuristic SOC Dashboard: {os.path.abspath(dash_file)}")
        webbrowser.open(f"file://{os.path.abspath(dash_file)}")
        return

    # Default: Launch Interactive Master GUI
    from app_gui import launch_gui
    launch_gui(args.file)


if __name__ == "__main__":
    main()
