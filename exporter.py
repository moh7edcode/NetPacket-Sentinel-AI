"""
NetPacket Inspector - State-of-the-Art Interactive Forensic Single-Page Application (SPA) Report Exporter
Generates self-contained, highly interactive HTML forensic reports with dynamic IP drilldowns, live packet filtering,
MITRE ATT&CK kill-chain timelines, file carving artifacts, and SOC incident response playbooks.
"""

import json
import csv
import os
import datetime
from typing import List, Dict, Any

from pcap_parser import ParsedPacket
from analyzer import TrafficAnalyzer
from threat_detector import ThreatDetector, ThreatAlert
from stream_profiler import StreamProfiler
from threat_intel import ThreatIntelEngine
from geo_resolver import GeoResolverEngine
from file_carver import FileCarverEngine
from ai_triage_playbook import IncidentTriageEngine
from assets_data import EMBLEM_B64


class PacketExporter:
    """Exports structured data and master interactive single-page forensic reports."""

    @staticmethod
    def export_json(packets: List[ParsedPacket], filepath: str, alerts: List[ThreatAlert] = None):
        alerts = alerts or ThreatDetector(packets).run_all_checks()
        profiler = StreamProfiler(packets, alerts)
        intel = ThreatIntelEngine()
        iocs = intel.extract_iocs_from_packets(packets)
        geo_data = GeoResolverEngine.resolve_all_capture_ips(packets)
        carved_files = [f.to_dict() for f in FileCarverEngine.carve_files_from_packets(packets)]
        timeline = IncidentTriageEngine.generate_attack_timeline(alerts, packets)
        playbook = IncidentTriageEngine.generate_remediation_playbook(alerts, profiler.get_all_ip_profiles())

        data = {
            "Metadata": {
                "Timestamp": datetime.datetime.now().isoformat(),
                "Total_Packets": len(packets),
                "Total_Threats_Detected": len(alerts)
            },
            "Threat_Alerts": [a.to_dict() for a in alerts],
            "Attack_Timeline": timeline,
            "SOC_Remediation_Playbook": playbook,
            "IP_Profiles": profiler.get_all_ip_profiles(),
            "IP_Geolocation_And_Domains": geo_data,
            "Extracted_Carved_Files": carved_files,
            "Conversation_Streams": profiler.get_all_streams(),
            "Threat_Intelligence": {
                "IP_Reputations": [intel.lookup_ip_deep(ip) for ip in iocs.get("Public_IPs", [])],
                "Domain_Reputations": [intel.lookup_domain_deep(d) for d in iocs.get("Domains", [])],
                "Payload_Hashes": iocs.get("Payload_Hashes", [])
            },
            "Packets": [p.to_dict() for p in packets]
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

    @staticmethod
    def export_csv(packets: List[ParsedPacket], filepath: str):
        fieldnames = ["No", "Time_Rel", "Source", "Destination", "Protocol", "Length", "Info"]
        with open(filepath, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for p in packets:
                writer.writerow({
                    "No": p.packet_num,
                    "Time_Rel": f"{p.rel_time:.6f}",
                    "Source": p.src,
                    "Destination": p.dst,
                    "Protocol": p.protocol,
                    "Length": p.captured_length,
                    "Info": p.info
                })

    @staticmethod
    def export_html_report(packets: List[ParsedPacket], filepath: str, source_filename: str = "Capture", vt_api_key: str = None):
        """Generates a master interactive single-page application (SPA) forensic HTML report."""
        analyzer = TrafficAnalyzer(packets)
        stats = analyzer.get_summary_statistics()
        proto_dist = analyzer.get_protocol_distribution()

        td = ThreatDetector(packets)
        alerts = td.run_all_checks()

        profiler = StreamProfiler(packets, alerts)
        ip_profiles = profiler.get_all_ip_profiles()
        streams = profiler.get_all_streams()

        intel = ThreatIntelEngine(vt_api_key)
        iocs = intel.extract_iocs_from_packets(packets)
        ip_lookups = {ip: intel.lookup_ip_deep(ip) for ip in iocs.get("Public_IPs", [])}
        domain_lookups = {d: intel.lookup_domain_deep(d) for d in iocs.get("Domains", [])}

        geo_data = GeoResolverEngine.resolve_all_capture_ips(packets)
        geo_map = {g["IP"]: g for g in geo_data}

        carved_files = FileCarverEngine.carve_files_from_packets(packets)
        timeline = IncidentTriageEngine.generate_attack_timeline(alerts, packets)
        playbook = IncidentTriageEngine.generate_remediation_playbook(alerts, ip_profiles)

        crit_count = sum(1 for a in alerts if a.severity == "CRITICAL")
        high_count = sum(1 for a in alerts if a.severity == "HIGH")
        med_count = sum(1 for a in alerts if a.severity == "MEDIUM")

        overall_threat = "CRITICAL RISK" if crit_count > 0 else ("HIGH RISK" if high_count > 0 else ("MODERATE RISK" if med_count > 0 else "NORMAL / LOW RISK"))
        threat_badge_bg = "#fef2f2" if crit_count > 0 else ("#fff7ed" if high_count > 0 else ("#fefce8" if med_count > 0 else "#f0fdf4"))
        threat_badge_border = "#fca5a5" if crit_count > 0 else ("#fdba74" if high_count > 0 else ("#fde047" if med_count > 0 else "#86efac"))
        threat_badge_color = "#dc2626" if crit_count > 0 else ("#ea580c" if high_count > 0 else ("#ca8a04" if med_count > 0 else "#16a34a"))

        # Prepare JSON payload for interactive client-side JS engine
        js_ip_data = {}
        for ip, prof in profiler.ip_profiles.items():
            g = geo_map.get(ip, {})
            vt = ip_lookups.get(ip, intel.lookup_ip_deep(ip))
            js_ip_data[ip] = {
                "profile": prof.to_dict(),
                "geo": g,
                "vt": vt
            }

        # Threat Alert Cards HTML
        alert_html_list = []
        for idx, a in enumerate(alerts):
            sev_class = a.severity.lower()
            ev_html = ""
            if a.evidence:
                ev_items = [f"<strong>{k.replace('_', ' ')}:</strong> <code>{v}</code>" for k, v in a.evidence.items()]
                ev_html = f"<div class='evidence-box'>{' | '.join(ev_items)}</div>"

            pkts_csv = ",".join(str(n) for n in a.related_packet_nums)
            pkts_str = ", ".join(f"#{num}" for num in a.related_packet_nums[:15])
            if len(a.related_packet_nums) > 15:
                pkts_str += f" (+{len(a.related_packet_nums) - 15} more)"

            alert_html_list.append(f"""
            <div class="threat-card threat-{sev_class}" id="threat-card-{idx}">
              <div class="threat-head">
                <div>
                  <span class="sev-badge sev-{sev_class}">{a.severity}</span>
                  <span class="threat-title">{a.title}</span>
                  <span class="mitre-tag">{a.mitre_technique_id}</span>
                </div>
                <div class="threat-meta">
                  Source: <a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{a.source_ip}')">{a.source_ip}</a> &rarr; 
                  Target: <a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{a.target_ip}')">{a.target_ip}</a>
                </div>
              </div>
              <div class="threat-desc">{a.description}</div>
              {ev_html}
              <div class="threat-pkts">
                <strong>Trigger Packets ({len(a.related_packet_nums)}):</strong> <code>{pkts_str}</code>
                <button class="btn-filter-pkts" onclick="filterByPacketList('{pkts_csv}')">🎯 Filter Table for These Packets</button>
              </div>
            </div>
            """)
        threats_html = "".join(alert_html_list) if alert_html_list else "<div class='no-threats'>✅ No active malicious attack patterns identified in this capture.</div>"

        # Timeline HTML
        timeline_rows = []
        for t in timeline:
            pkts_csv = ",".join(str(p) for p in t["Trigger_Packets"])
            timeline_rows.append(f"""
            <div class="timeline-item">
              <div class="timeline-time">+{t['Timestamp_Rel']}s</div>
              <div class="timeline-content">
                <div class="timeline-header">
                  <span class="phase-tag">{t['Kill_Chain_Phase']}</span>
                  <strong style="color:#1e3a8a;">{t['Incident_Title']}</strong>
                  <span class="mitre-tag">{t['MITRE_ID']}</span>
                </div>
                <div style="font-size:12px; color:#475569; margin:4px 0;">{t['Description']}</div>
                <div style="font-size:11px;">
                  Attacker: <a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{t['Attacker']}')">{t['Attacker']}</a> &rarr; 
                  Victim: <a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{t['Victim']}')">{t['Victim']}</a> | 
                  <a href="javascript:void(0)" class="filter-link" onclick="filterByPacketList('{pkts_csv}')">View {len(t['Trigger_Packets'])} Packets</a>
                </div>
              </div>
            </div>
            """)
        timeline_html = "".join(timeline_rows)

        # SOC Remediation Playbook HTML
        playbook_rows = []
        for pb in playbook:
            p_class = "crit" if "P0" in pb["Priority"] else ("high" if "P1" in pb["Priority"] else "med")
            playbook_rows.append(f"""
            <div class="playbook-item pb-{p_class}">
              <div class="pb-header">
                <span class="pb-badge pb-badge-{p_class}">Step {pb['Step']} : {pb['Priority']}</span>
                <span class="pb-action">{pb['Action']}</span>
                <span class="pb-target">Target: <code>{pb['Target']}</code></span>
              </div>
              <div class="pb-instructions">{pb['Instructions']}</div>
              <div class="pb-rationale"><strong>Rationale:</strong> {pb['Rationale']}</div>
            </div>
            """)
        playbook_html = "".join(playbook_rows)

        # IP Geolocation Table HTML
        geo_rows = []
        for g in geo_data:
            doms_str = "<br>".join(g["Domain_Names"]) if g["Domain_Names"] else "(None)"
            is_priv = "<span class='badge' style='background:#f1f5f9; color:#475569; border:1px solid #cbd5e1;'>LAN</span>" if g["Is_Private"] else "<span class='badge' style='background:#ecfdf5; color:#047857; border:1px solid #6ee7b7;'>PUBLIC</span>"
            geo_rows.append(f"""
            <tr>
              <td><a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{g['IP']}')"><code>{g['IP']}</code></a> {is_priv}</td>
              <td style="color:#0284c7; font-weight:600;">{doms_str}</td>
              <td><strong>{g['Country']}</strong> <span style="color:#64748b; font-size:11px;">({g['Country_Code']})</span></td>
              <td>{g['City']}</td>
              <td><code>{g['ASN']}</code></td>
              <td style="font-size:11px; color:#64748b;">{g['ISP']}</td>
            </tr>
            """)
        geo_table_html = "".join(geo_rows)

        # Carved Files Table HTML
        carved_rows = []
        for cf in carved_files:
            pkts_csv = ",".join(str(p) for p in cf.packet_nums)
            carved_rows.append(f"""
            <tr>
              <td><code>#{cf.file_id}</code></td>
              <td style="font-weight:700; color:#1e3a8a;">{cf.filename}</td>
              <td><span class="badge" style="background:#f5f3ff; color:#6d28d9; border:1px solid #c4b5fd;">{cf.file_type}</span></td>
              <td>{cf.size_bytes} B</td>
              <td><a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{cf.source_ip}')">{cf.source_ip}</a> &rarr; <a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{cf.dest_ip}')">{cf.dest_ip}</a></td>
              <td><code style="font-size:11px;">{cf.sha256[:16]}...</code></td>
              <td><button class="btn-filter-pkts" onclick="filterByPacketList('{pkts_csv}')">Inspect Pkts</button></td>
            </tr>
            """)
        carved_table_html = "".join(carved_rows) if carved_rows else "<tr><td colspan='7' style='text-align:center; color:#64748b; padding:18px;'>No raw file objects carved in this stream.</td></tr>"

        # Packet Rows HTML (First 200)
        pkt_rows = []
        for p in packets[:200]:
            pkt_rows.append(f"""
            <tr class='proto-{p.protocol.lower()} pkt-row' data-pkt="{p.packet_num}" data-proto="{p.protocol.lower()}" data-src="{p.src}" data-dst="{p.dst}" data-info="{p.info.lower()}">
              <td><strong>#{p.packet_num}</strong></td>
              <td style="color:#64748b;">{p.rel_time:.6f}</td>
              <td><a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{p.src}')"><code>{p.src}</code></a></td>
              <td><a href="javascript:void(0)" class="ip-link" onclick="openIpModal('{p.dst}')"><code>{p.dst}</code></a></td>
              <td><span class='badge badge-{p.protocol.lower()}'>{p.protocol}</span></td>
              <td>{p.captured_length} B</td>
              <td class='info-col'>{p.info}</td>
            </tr>
            """)
        pkt_table_html = "".join(pkt_rows)

        # Full Master Standalone HTML Template with Embedded JS Engine
        html_template = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NetPacket Inspector Pro - Executive Forensic SPA Report</title>
<style>
  :root {{
    --bg-page: #f8fafc;
    --bg-card: #ffffff;
    --bg-subtle: #f0f7ff;
    --border-blue: #bfdbfe;
    --border-blue-dark: #2563eb;
    --text-navy: #1e3a8a;
    --text-body: #0f172a;
    --text-muted: #64748b;
    --accent-blue: #2563eb;
    --accent-sky: #0284c7;
    --accent-red: #dc2626;
    --accent-orange: #ea580c;
    --accent-green: #16a34a;
    --accent-purple: #7c3aed;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{
    background-color: var(--bg-page);
    color: var(--text-body);
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
    padding: 24px;
    line-height: 1.5;
  }}
  .header {{
    background: var(--bg-card);
    border: 1.5px solid var(--border-blue);
    border-radius: 14px;
    padding: 20px 26px;
    margin-bottom: 24px;
    display: flex;
    justify-content: space-between;
    align-items: center;
    flex-wrap: wrap;
    gap: 16px;
    box-shadow: 0 4px 16px rgba(37, 99, 235, 0.08);
  }}
  .header h1 {{ font-size: 22px; color: var(--text-navy); font-weight: 800; display: flex; align-items: center; gap: 10px; }}
  .header .meta {{ color: var(--text-muted); font-size: 13px; margin-top: 4px; }}
  .header-badge {{
    display: inline-block;
    padding: 3px 10px;
    border-radius: 999px;
    font-size: 11px;
    font-weight: 800;
    letter-spacing: 0.6px;
    background: #eff6ff;
    color: var(--accent-blue);
    border: 1px solid var(--border-blue);
    margin-left: 8px;
    vertical-align: middle;
  }}
  .posture-badge {{
    background: {threat_badge_bg};
    border: 2px solid {threat_badge_border};
    color: {threat_badge_color};
    padding: 10px 20px;
    border-radius: 10px;
    font-size: 14px;
    font-weight: 800;
    letter-spacing: 0.5px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(0, 0, 0, 0.05);
  }}

  .grid-4 {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 16px; margin-bottom: 24px; }}
  .metric-card {{
    background: var(--bg-card);
    border: 1.5px solid var(--border-blue);
    border-top: 4px solid var(--accent-blue);
    border-radius: 12px;
    padding: 18px;
    text-align: center;
    box-shadow: 0 2px 8px rgba(37, 99, 235, 0.05);
    transition: transform 0.2s, box-shadow 0.2s;
  }}
  .metric-card:hover {{
    transform: translateY(-2px);
    box-shadow: 0 6px 16px rgba(37, 99, 235, 0.12);
  }}
  .metric-card .title {{ font-size: 11px; color: var(--text-navy); font-weight: 800; text-transform: uppercase; letter-spacing: 0.6px; }}
  .metric-card .value {{ font-size: 28px; font-weight: 800; color: var(--text-body); margin-top: 6px; }}
  .val-crit {{ color: var(--accent-red) !important; }}
  .val-high {{ color: var(--accent-orange) !important; }}

  .section {{
    background: var(--bg-card);
    border: 1.5px solid var(--border-blue);
    border-radius: 14px;
    padding: 22px;
    margin-bottom: 24px;
    box-shadow: 0 4px 16px rgba(37, 99, 235, 0.06);
  }}
  .section h2 {{
    font-size: 16px;
    color: var(--text-navy);
    font-weight: 800;
    margin-bottom: 18px;
    border-bottom: 1.5px solid #eff6ff;
    padding-bottom: 10px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }}

  .threat-card {{
    background: var(--bg-card);
    border: 1.5px solid var(--border-blue);
    border-left: 5px solid var(--accent-blue);
    border-radius: 8px;
    padding: 14px 18px;
    margin-bottom: 14px;
    box-shadow: 0 2px 6px rgba(15, 23, 42, 0.04);
  }}
  .threat-critical {{ border-left-color: var(--accent-red); background: #fef2f2; }}
  .threat-high {{ border-left-color: var(--accent-orange); background: #fff7ed; }}
  .threat-medium {{ border-left-color: #f59e0b; background: #fffbeb; }}

  .threat-head {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 6px; flex-wrap: wrap; gap: 8px; }}
  .threat-title {{ font-size: 14px; font-weight: 800; color: var(--text-navy); margin-left: 6px; }}
  .threat-meta {{ font-size: 12px; color: var(--text-muted); }}
  .threat-desc {{ font-size: 13px; color: var(--text-body); margin-bottom: 8px; }}
  .threat-pkts {{ font-size: 12px; color: var(--text-navy); display: flex; align-items: center; justify-content: space-between; flex-wrap: wrap; gap: 8px; margin-top: 6px; }}

  .sev-badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px; font-size: 10px; font-weight: 800; text-transform: uppercase; }}
  .sev-critical {{ background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }}
  .sev-high {{ background: #ffedd5; color: #c2410c; border: 1px solid #fb923c; }}
  .sev-medium {{ background: #fef3c7; color: #b45309; border: 1px solid #fcd34d; }}
  .mitre-tag {{ background: #eff6ff; border: 1px solid var(--border-blue); color: var(--accent-blue); font-size: 11px; font-weight: 700; padding: 2px 6px; border-radius: 4px; margin-left: 6px; }}

  .evidence-box {{
    background: #f8fafc;
    border: 1px dashed var(--border-blue);
    padding: 8px 12px;
    border-radius: 6px;
    font-size: 12px;
    color: var(--text-body);
    margin-bottom: 8px;
  }}

  /* Interactive Elements */
  .ip-link {{ color: var(--accent-blue); text-decoration: none; font-weight: 700; cursor: pointer; border-bottom: 1px dashed var(--border-blue); }}
  .ip-link:hover {{ color: var(--accent-sky); text-decoration: underline; }}
  .filter-link {{ color: var(--accent-green); text-decoration: none; font-size: 12px; font-weight: 600; cursor: pointer; }}
  .filter-link:hover {{ text-decoration: underline; }}

  .btn-filter-pkts {{
    background: var(--accent-blue);
    color: #ffffff;
    border: none;
    padding: 4px 10px;
    border-radius: 6px;
    font-size: 11px;
    font-weight: 700;
    cursor: pointer;
    box-shadow: 0 1px 4px rgba(37, 99, 235, 0.2);
    transition: background 0.15s;
  }}
  .btn-filter-pkts:hover {{ background: #1d4ed8; }}

  /* Timeline */
  .timeline-item {{ display: flex; gap: 16px; margin-bottom: 16px; position: relative; }}
  .timeline-time {{ min-width: 75px; font-family: monospace; font-size: 12px; color: var(--accent-blue); font-weight: 800; text-align: right; padding-top: 4px; }}
  .timeline-content {{ background: var(--bg-card); border: 1.5px solid var(--border-blue); border-left: 4px solid var(--accent-blue); border-radius: 8px; padding: 12px 16px; flex-grow: 1; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.03); }}
  .timeline-header {{ display: flex; align-items: center; gap: 8px; flex-wrap: wrap; margin-bottom: 4px; }}
  .phase-tag {{ background: #e0e7ff; color: var(--accent-blue); font-size: 10px; font-weight: 800; padding: 2px 6px; border-radius: 4px; text-transform: uppercase; border: 1px solid var(--border-blue); }}

  /* Playbook */
  .playbook-item {{ background: var(--bg-card); border: 1.5px solid var(--border-blue); border-radius: 8px; padding: 14px 18px; margin-bottom: 12px; border-left: 5px solid; box-shadow: 0 2px 6px rgba(15, 23, 42, 0.03); }}
  .pb-crit {{ border-left-color: var(--accent-red); background: #fef2f2; }}
  .pb-high {{ border-left-color: var(--accent-orange); background: #fff7ed; }}
  .pb-med {{ border-left-color: #f59e0b; background: #fffbeb; }}
  .pb-header {{ display: flex; align-items: center; gap: 10px; margin-bottom: 6px; flex-wrap: wrap; }}
  .pb-badge {{ font-size: 11px; font-weight: 800; padding: 2px 8px; border-radius: 4px; text-transform: uppercase; }}
  .pb-badge-crit {{ background: #fee2e2; color: #b91c1c; border: 1px solid #f87171; }}
  .pb-badge-high {{ background: #ffedd5; color: #c2410c; border: 1px solid #fb923c; }}
  .pb-badge-med {{ background: #fef3c7; color: #b45309; border: 1px solid #fcd34d; }}
  .pb-action {{ font-weight: 800; color: var(--text-navy); font-size: 14px; }}
  .pb-target {{ font-size: 12px; color: var(--text-muted); margin-left: auto; }}
  .pb-instructions {{ font-size: 13px; color: var(--text-body); margin-bottom: 6px; }}
  .pb-rationale {{ font-size: 12px; color: var(--text-muted); }}

  /* Tables */
  table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  th {{ background: #f0f7ff; color: var(--text-navy); padding: 10px 14px; font-weight: 700; border-bottom: 2px solid var(--border-blue); text-align: left; }}
  td {{ padding: 10px 14px; border-bottom: 1px solid #f1f5f9; color: var(--text-body); }}
  tr:hover {{ background: #f8fafc; }}
  code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; color: var(--accent-blue); background: #f1f5f9; padding: 2px 6px; border-radius: 4px; font-size: 12px; }}

  .badge {{ display: inline-block; padding: 2px 7px; border-radius: 4px; font-size: 10px; font-weight: 700; margin: 1px; }}
  .badge-tcp {{ background: #eff6ff; color: #1d4ed8; border: 1px solid #93c5fd; }}
  .badge-udp {{ background: #ecfdf5; color: #047857; border: 1px solid #6ee7b7; }}
  .badge-dns {{ background: #f0fdfa; color: #0f766e; border: 1px solid #5eead4; }}
  .badge-http {{ background: #f5f3ff; color: #6d28d9; border: 1px solid #c4b5fd; }}
  .badge-icmp {{ background: #fffbeb; color: #b45309; border: 1px solid #fcd34d; }}
  .badge-arp {{ background: #fdf2f8; color: #be185d; border: 1px solid #f9a8d4; }}

  .info-col {{ word-break: break-all; font-family: monospace; font-size: 12px; color: var(--text-body); }}

  /* Interactive Modal */
  .modal-overlay {{
    display: none;
    position: fixed;
    top: 0; left: 0; right: 0; bottom: 0;
    background: rgba(15, 23, 42, 0.6);
    z-index: 1000;
    align-items: center;
    justify-content: center;
    backdrop-filter: blur(4px);
  }}
  .modal-box {{
    background: #ffffff;
    border: 2px solid var(--accent-blue);
    border-radius: 14px;
    width: 90%;
    max-width: 750px;
    max-height: 85vh;
    overflow-y: auto;
    padding: 24px;
    box-shadow: 0 20px 30px -5px rgba(37, 99, 235, 0.2);
  }}
  .modal-header {{ display: flex; justify-content: space-between; align-items: center; border-bottom: 1.5px solid var(--border-blue); padding-bottom: 12px; margin-bottom: 16px; }}
  .modal-title {{ font-size: 18px; font-weight: 800; color: var(--text-navy); }}
  .btn-close {{ background: transparent; border: none; color: var(--text-muted); font-size: 22px; cursor: pointer; }}
  .btn-close:hover {{ color: var(--accent-red); }}

  .search-bar-wrap {{ margin-bottom: 14px; display: flex; gap: 8px; align-items: center; }}
  .search-input {{
    background: #ffffff;
    border: 1.5px solid var(--border-blue);
    color: var(--text-body);
    padding: 9px 14px;
    border-radius: 8px;
    font-size: 13px;
    flex-grow: 1;
    font-family: monospace;
    box-shadow: 0 1px 4px rgba(37, 99, 235, 0.05);
  }}
  .search-input:focus {{ outline: none; border-color: var(--accent-blue); box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.15); }}
</style>
</head>
<body>

<div class="header">
  <div style="display:flex; align-items:center; gap:16px;">
    <div style="width:64px; height:64px; border-radius:50%; border:2.5px solid var(--accent-blue); background:#ffffff; overflow:hidden; box-shadow:0 0 14px rgba(37,99,235,0.25); flex-shrink:0; display:flex; align-items:center; justify-content:center;">
      <img src="{EMBLEM_B64}" alt="Kali x Wireshark Cyber Defense Emblem" style="width:100%; height:100%; object-fit:cover;">
    </div>
    <div>
      <div style="display:flex; align-items:center; gap:8px;">
        <h1 style="font-size:22px; color:var(--text-navy); margin:0;">⚡ NetPacket Inspector Pro</h1>
        <span class="header-badge">SMART SOC PLATFORM</span>
      </div>
      <div style="font-size:12px; color:var(--accent-blue); font-weight:700; margin-top:3px;">منظومة التحليل الجنائي السيبراني واعتراض الحزم المتقدمة</div>
      <div class="meta" style="margin-top:3px;">Target Capture: <strong style="color:var(--text-navy);">{source_filename}</strong> | Generated: <strong>{datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}</strong></div>
    </div>
  </div>
  <div class="posture-badge">
    SECURITY POSTURE<br>{overall_threat}
  </div>
</div>

<div class="grid-4">
  <div class="metric-card">
    <div class="title">Critical Incidents</div>
    <div class="value val-crit">{crit_count}</div>
  </div>
  <div class="metric-card">
    <div class="title">High Severity Alerts</div>
    <div class="value val-high">{high_count}</div>
  </div>
  <div class="metric-card">
    <div class="title">Total Packets</div>
    <div class="value">{stats.get('Total_Packets')}</div>
  </div>
  <div class="metric-card">
    <div class="title">Total Volume</div>
    <div class="value">{stats.get('Total_Bytes_Formatted')}</div>
  </div>
</div>

<div class="section">
  <h2><span>🛡️ Identified Malicious Tactics & Network Incidents (MITRE ATT&CK)</span></h2>
  {threats_html}
</div>

<div class="section">
  <h2><span>⏳ Chronological Cyber Attack Lifecycle (Kill-Chain Timeline)</span></h2>
  <div class="timeline-container">
    {timeline_html}
  </div>
</div>

<div class="section">
  <h2><span>📋 Automated SOC Incident Response Remediation Playbook</span></h2>
  {playbook_html}
</div>

<div class="section">
  <h2><span>🗺️ IP Geolocation & Domain Name Resolution Map</span></h2>
  <div style="overflow-x: auto;">
    <table>
      <thead>
        <tr>
          <th>Endpoint IP</th>
          <th>Correlated Domains / Services</th>
          <th>Country</th>
          <th>City / Region</th>
          <th>ASN & Routing</th>
          <th>ISP / Organization</th>
        </tr>
      </thead>
      <tbody>
        {geo_table_html}
      </tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2><span>📁 Extracted Network File Artifacts (File Carving)</span></h2>
  <div style="overflow-x: auto;">
    <table>
      <thead>
        <tr>
          <th>ID</th>
          <th>Filename</th>
          <th>Object Type</th>
          <th>Size</th>
          <th>Transmission Flow</th>
          <th>SHA-256 Hash</th>
          <th>Action</th>
        </tr>
      </thead>
      <tbody>
        {carved_table_html}
      </tbody>
    </table>
  </div>
</div>

<div class="section">
  <h2>
    <span>🔍 Live Dissected Packet Stream</span>
    <span id="pkt-count-badge" style="font-size:12px; color:var(--text-muted); font-weight:normal;">Showing 200 packets</span>
  </h2>
  
  <div class="search-bar-wrap">
    <input type="text" id="live-search-box" class="search-input" placeholder="🔍 Live Interactive Filter: Type any IP, Protocol (tcp, dns, http), Port, or Search Text..." oninput="onLiveFilterChanged()">
    <button class="btn-filter-pkts" style="padding:9px 14px;" onclick="resetLiveFilter()">Clear Filter</button>
  </div>

  <div style="overflow-x: auto; max-height: 520px; overflow-y: auto;">
    <table id="packet-main-table">
      <thead>
        <tr>
          <th>#</th>
          <th>Time (s)</th>
          <th>Source IP</th>
          <th>Destination IP</th>
          <th>Protocol</th>
          <th>Length</th>
          <th>Summary / Dissection Info</th>
        </tr>
      </thead>
      <tbody id="packet-tbody">
        {pkt_table_html}
      </tbody>
    </table>
  </div>
</div>

<!-- Dynamic Interactive IP Investigation Modal Dialog -->
<div id="ipModal" class="modal-overlay" onclick="closeModalOnOutsideClick(event)">
  <div class="modal-box">
    <div class="modal-header">
      <div class="modal-title" id="m-ip-title">🌐 IP Forensic Telemetry</div>
      <button class="btn-close" onclick="closeIpModal()">&times;</button>
    </div>
    <div id="m-ip-body" style="font-size:13px; line-height:1.6;">
      <!-- Populated dynamically via JS -->
    </div>
    <div style="margin-top:18px; text-align:right;">
      <button id="m-btn-filter-ip" class="btn-filter-pkts" style="padding:8px 16px; font-size:12px;" onclick="filterTableByCurrentModalIp()">🎯 Filter Packet Stream for this IP</button>
    </div>
  </div>
</div>

<!-- Embedded JS Engine for Client-Side Interactivity -->
<script>
  const IP_STORE = {json.dumps(js_ip_data)};
  let currentModalIp = "";

  function openIpModal(ip) {{
    currentModalIp = ip;
    const modal = document.getElementById("ipModal");
    const title = document.getElementById("m-ip-title");
    const body = document.getElementById("m-ip-body");

    const data = IP_STORE[ip] || {{}};
    const prof = data.profile || {{}};
    const geo = data.geo || {{}};
    const vt = data.vt || {{}};

    title.innerHTML = `🌐 Deep Forensic Investigation: <code>${{ip}}</code>`;

    let vtEnginesHtml = "";
    if (vt.Engine_Detections && vt.Engine_Detections.length > 0) {{
      vtEnginesHtml = `<div style="margin-top:10px; background:#fef2f2; border:1.5px solid #f87171; border-radius:8px; padding:12px;">
        <strong style="color:#b91c1c;">🚨 Security Engines Flagging this Target:</strong>
        <ul style="margin:6px 0 0 16px; color:#7f1d1d;">
          ${{vt.Engine_Detections.map(e => `<li><strong>${{e.Engine}}</strong>: ${{e.Category}} (${{e.Result}})</li>`).join('')}}
        </ul>
      </div>`;
    }}

    body.innerHTML = `
      <div style="display:grid; grid-template-columns: 1fr 1fr; gap:14px; margin-bottom:14px;">
        <div style="background:#f8fafc; border:1.5px solid var(--border-blue); padding:14px; border-radius:8px;">
          <div style="color:var(--text-navy); font-size:11px; font-weight:700; text-transform:uppercase;">Threat Classification</div>
          <div style="font-size:16px; font-weight:800; margin-top:2px; color:${{prof.Threat_Level === 'MALICIOUS' ? '#dc2626' : (prof.Threat_Level === 'SUSPICIOUS' ? '#ea580c' : '#16a34a')}}">
            ${{prof.Threat_Level || 'CLEAN / UNRATED'}} (Score: ${{prof.Threat_Score || 0}}/100)
          </div>
          <div style="margin-top:4px; font-size:12px; color:#475569;">Packets Tx: ${{prof.Packets_Sent || 0}} | Rx: ${{prof.Packets_Recv || 0}}</div>
        </div>
        <div style="background:#f8fafc; border:1.5px solid var(--border-blue); padding:14px; border-radius:8px;">
          <div style="color:var(--text-navy); font-size:11px; font-weight:700; text-transform:uppercase;">VirusTotal Verdict</div>
          <div style="font-size:16px; font-weight:800; margin-top:2px; color:${{vt.Verdict && vt.Verdict.includes('MALICIOUS') ? '#dc2626' : '#16a34a'}}">
            ${{vt.Verdict || 'CLEAN'}}
          </div>
          <div style="margin-top:4px; font-size:12px; color:#475569;">Detections: ${{vt.Detections || '0/89'}}</div>
        </div>
      </div>

      <div style="background:#f8fafc; border:1.5px solid var(--border-blue); padding:16px; border-radius:8px; margin-bottom:12px;">
        <h4 style="color:var(--text-navy); margin-bottom:8px; font-weight:800;">🗺️ Geolocation & Routing Intelligence</h4>
        <div style="color:#0f172a; margin-bottom:3px;"><strong>Country:</strong> ${{geo.Country || 'Global Internet'}} (${{geo.Country_Code || 'N/A'}})</div>
        <div style="color:#0f172a; margin-bottom:3px;"><strong>City / Region:</strong> ${{geo.City || 'N/A'}}</div>
        <div style="color:#0f172a; margin-bottom:3px;"><strong>ASN & Route:</strong> <code>${{geo.ASN || vt.ASN || 'Standard Route'}}</code></div>
        <div style="color:#0f172a; margin-bottom:3px;"><strong>ISP / Organization:</strong> ${{geo.ISP || vt.Owner || 'N/A'}}</div>
        <div style="color:#0f172a;"><strong>Correlated Domains:</strong> ${{geo.Domain_Names ? geo.Domain_Names.join(', ') : 'None'}}</div>
      </div>

      ${{vtEnginesHtml}}
    `;

    modal.style.display = "flex";
  }}

  function closeIpModal() {{
    document.getElementById("ipModal").style.display = "none";
  }}

  function closeModalOnOutsideClick(e) {{
    if (e.target.id === "ipModal") closeIpModal();
  }}

  function filterTableByCurrentModalIp() {{
    if (!currentModalIp) return;
    document.getElementById("live-search-box").value = currentModalIp;
    onLiveFilterChanged();
    closeIpModal();
    document.getElementById("packet-main-table").scrollIntoView({{ behavior: "smooth" }});
  }}

  function filterByPacketList(pktsCsv) {{
    const pktSet = new Set(pktsCsv.split(",").map(s => s.trim()));
    const rows = document.querySelectorAll(".pkt-row");
    let count = 0;

    rows.forEach(r => {{
      const num = r.getAttribute("data-pkt");
      if (pktSet.has(num)) {{
        r.style.display = "";
        count++;
      }} else {{
        r.style.display = "none";
      }}
    }});

    document.getElementById("live-search-box").value = "Packets: " + pktsCsv.split(",").slice(0, 5).join(", ") + "...";
    document.getElementById("pkt-count-badge").innerText = `Filtered: ${{count}} matching trigger packets`;
    document.getElementById("packet-main-table").scrollIntoView({{ behavior: "smooth" }});
  }}

  function onLiveFilterChanged() {{
    const query = document.getElementById("live-search-box").value.trim().toLowerCase();
    const rows = document.querySelectorAll(".pkt-row");
    let count = 0;

    rows.forEach(r => {{
      if (!query) {{
        r.style.display = "";
        count++;
        return;
      }}
      const num = r.getAttribute("data-pkt") || "";
      const proto = r.getAttribute("data-proto") || "";
      const src = (r.getAttribute("data-src") || "").toLowerCase();
      const dst = (r.getAttribute("data-dst") || "").toLowerCase();
      const info = (r.getAttribute("data-info") || "").toLowerCase();

      if (num === query || proto.includes(query) || src.includes(query) || dst.includes(query) || info.includes(query)) {{
        r.style.display = "";
        count++;
      }} else {{
        r.style.display = "none";
      }}
    }});

    document.getElementById("pkt-count-badge").innerText = `Showing ${{count}} of ${{rows.length}} packets`;
  }}

  function resetLiveFilter() {{
    document.getElementById("live-search-box").value = "";
    onLiveFilterChanged();
  }}
</script>
</body>
</html>
"""
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_template)
