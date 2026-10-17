"""Analysis pipeline — faithful mirror of CyberBridgeAPI._process_pcap_file and
run_ai_analysis from app_gui.py, wrapped with per-stage progress emission.
Engine modules are called as-is; nothing in them is modified."""
import os
import threading
from typing import Any, Dict, List, Optional

from analyzer import TrafficAnalyzer
from config_manager import ConfigManager
from file_carver import FileCarverEngine
from geo_resolver import GeoResolverEngine
from network_attacks_catalog import AttackInspectorEngine
from payload_decoder import PayloadDecoder
from stream_follower import StreamFollower
from stream_profiler import StreamProfiler
from threat_detector import ThreatDetector
from threat_intel import ThreatIntelEngine
from ai_triage_playbook import IncidentTriageEngine

from backend.serializers import (
    alerts_to_list,
    catalog_results_to_list,
    follow_stream_result,
    packet_summary,
)
from backend.sessions import AnalysisSession, Job

intel_engine_lock = threading.Lock()
_shared_intel_engine: Optional[ThreatIntelEngine] = None


def get_intel_engine() -> ThreatIntelEngine:
    global _shared_intel_engine
    with intel_engine_lock:
        if _shared_intel_engine is None:
            _shared_intel_engine = ThreatIntelEngine()
        return _shared_intel_engine


def reset_intel_engine(api_key: Optional[str]):
    global _shared_intel_engine
    with intel_engine_lock:
        _shared_intel_engine = ThreatIntelEngine(api_key if api_key else None)


# ---------------------------------------------------------------------------
# Full pipeline (mirrors _process_pcap_file, steps 1-15)
# ---------------------------------------------------------------------------

def run_full_pipeline(job: Job, sess: AnalysisSession):
    emit = job.emit

    emit("parse", 5, "Reading PCAP file")
    packets = PcapReader_read(job.filepath)
    sess.all_packets = packets

    emit("analyze", 15, "Computing traffic statistics")
    analyzer = TrafficAnalyzer(packets)
    stats = analyzer.get_summary_statistics()
    proto_dist = analyzer.get_protocol_distribution()

    emit("threats", 25, "Running MITRE ATT&CK threat detection")
    sess.detected_alerts = ThreatDetector(packets).run_all_checks()

    emit("streams", 32, "Profiling conversations and host behavior")
    sess.stream_profiler = StreamProfiler(packets, sess.detected_alerts)
    ip_profiles = sess.stream_profiler.get_all_ip_profiles()
    streams = sess.stream_profiler.get_all_streams()

    emit("catalog", 38, "Matching network attacks catalog")
    sess.catalog_results = AttackInspectorEngine.match_loaded_packets(packets, sess.detected_alerts)

    emit("geo", 45, "Resolving geolocation, ASN and domains")
    try:
        sess.geo_results = GeoResolverEngine.resolve_all_capture_ips(packets)
    except Exception as e:  # never fail the pipeline on outbound geo lookups
        sess.geo_results = []
        emit("geo", 45, f"Geo lookup degraded: {e}")
    geo_map = {g["IP"]: g for g in sess.geo_results}

    emit("carve", 52, "Carving files and payloads")
    sess.carved_files = FileCarverEngine.carve_files_from_packets(packets)

    emit("playbook", 58, "Generating kill-chain timeline and SOC playbook")
    sess.attack_timeline = IncidentTriageEngine.generate_attack_timeline(sess.detected_alerts, packets)
    sess.soc_playbook = IncidentTriageEngine.generate_remediation_playbook(sess.detected_alerts, ip_profiles)

    emit("intel", 64, "Extracting IoCs and reputation lookups")
    intel_engine = get_intel_engine()
    iocs = intel_engine.extract_iocs_from_packets(packets)
    ip_lookups = [intel_engine.lookup_ip_deep(ip) for ip in iocs.get("Public_IPs", [])]
    domain_lookups = [intel_engine.lookup_domain_deep(d) for d in iocs.get("Domains", [])]

    defcon = compute_defcon(sess.detected_alerts)
    crit, high, med, low = defcon["critical"], defcon["high"], defcon["medium"], defcon["low"]

    emit("topology", 70, "Building network topology graph")
    nodes, links = build_topology(ip_profiles, streams, geo_map)

    emit("timeline_series", 74, "Bucketing traffic timeline")
    sess.timeline_series = build_timeline_series(packets, sess.detected_alerts)

    total_count = len(packets)
    total_carved_bytes = sum(cf.size_bytes for cf in sess.carved_files)

    emit("ai", 78, "Pre-warming hybrid AI Sentinel engine")
    sess.ai_results = None
    try:
        run_ai(sess)
    except Exception as e:
        print(f"[!] AI pre-warm error: {e}")

    sess.payload = {
        "has_data": True,
        "job_id": job.id,
        "filename": os.path.basename(job.filepath),
        "filepath": job.filepath,
        "total_packets": total_count,
        "summary_stats": stats,
        "protocol_dist": proto_dist,
        "defcon": defcon,
        "hud": {
            "total_packets": stats.get("Total_Packets", total_count),
            "total_bytes_fmt": stats.get("Total_Bytes_Formatted", "0 B"),
            "duration": stats.get("Duration_Seconds", 0.0),
            "packet_rate": stats.get("Packet_Rate", "0 pkts/s"),
            "threats_count": len(sess.detected_alerts),
            "critical_count": crit,
            "high_count": high,
            "carved_count": len(sess.carved_files),
            "carved_bytes": total_carved_bytes,
            "endpoints_count": len(ip_profiles),
            "streams_count": len(streams),
            "posture": defcon["posture"],
            "intel_status": "Threatrix Feed - OK (Active)",
        },
        "threats": alerts_to_list(sess.detected_alerts),
        "topology": {"nodes": nodes, "links": links},
        "catalog": catalog_results_to_list(sess.catalog_results),
        "geo": sess.geo_results,
        "carved": [cf.to_dict() for cf in sess.carved_files],
        "timeline": sess.attack_timeline,
        "playbook": sess.soc_playbook,
        "ip_profiles": ip_profiles,
        "streams": streams,
        "intel": {
            "public_ips": ip_lookups,
            "domains": domain_lookups,
            "saved_key": ConfigManager.get_vt_api_key() or "",
        },
    }
    if sess.ai_results:
        sess.payload["ai_data"] = sess.ai_results
    emit("done", 100, "Analysis complete")


def PcapReader_read(filepath: str):
    from pcap_parser import PcapReader
    return PcapReader.read_file(filepath)


def compute_defcon(alerts) -> Dict[str, Any]:
    crit = sum(1 for a in alerts if a.severity == "CRITICAL")
    high = sum(1 for a in alerts if a.severity == "HIGH")
    med = sum(1 for a in alerts if a.severity == "MEDIUM")
    low = sum(1 for a in alerts if a.severity == "LOW")
    if crit > 0:
        level, title, posture, color = 1, "DEFCON 1 - CRITICAL HOSTILE INTRUSION", "CRITICAL THREAT", "#ef4444"
    elif high > 0:
        level, title, posture, color = 2, "DEFCON 2 - SEVERE EXPLOITATION RISK", "ELEVATED RISK", "#f97316"
    elif med > 0:
        level, title, posture, color = 3, "DEFCON 3 - ELEVATED ANOMALOUS ACTIVITY", "MODERATE RISK", "#eab308"
    elif low > 0:
        level, title, posture, color = 4, "DEFCON 4 - GUARDED RECONNAISSANCE SIGNALS", "LOW RISK", "#3b82f6"
    else:
        level, title, posture, color = 5, "DEFCON 5 - NORMAL DEFENSE POSTURE", "SYSTEMS NOMINAL", "#10b981"
    return {
        "level": level, "title": title, "posture": posture, "posture_color": color,
        "critical": crit, "high": high, "medium": med, "low": low,
    }


def build_topology(ip_profiles, streams, geo_map):
    nodes = []
    node_ids = set()
    for prof in ip_profiles:
        ip = prof["IP"]
        lvl = prof["Threat_Level"]
        is_priv = GeoResolverEngine.is_private_ip(ip)
        color = ("#ef4444" if lvl == "MALICIOUS"
                 else "#f97316" if lvl == "SUSPICIOUS"
                 else "#10b981" if is_priv else "#00f3ff")
        g = geo_map.get(ip, {})
        nodes.append({
            "id": ip, "label": ip, "color": color,
            "packets": prof["Total_Packets"], "threat_level": lvl,
            "threat_score": prof.get("Threat_Score", 0), "is_private": is_priv,
            "country": g.get("Country", "Unknown"), "isp": g.get("ISP", "N/A"),
            "bytes": prof["Total_Bytes"],
        })
        node_ids.add(ip)
    links = []
    for s in streams:
        c_ip = s["Client"].split(":")[0]
        s_ip = s["Server"].split(":")[0]
        if c_ip in node_ids and s_ip in node_ids:
            links.append({
                "source": c_ip, "target": s_ip, "protocol": s["Protocol"],
                "packets": s["Packet_Count"], "bytes": s["Total_Bytes"],
            })
    return nodes, links


def build_timeline_series(packets, alerts, bucket_seconds: float = 1.0):
    """Per-second packet/byte buckets + alert markers (new, for the dashboard chart)."""
    buckets: Dict[int, Dict[str, Any]] = {}
    for p in packets:
        idx = int(p.rel_time // bucket_seconds)
        b = buckets.get(idx)
        if b is None:
            b = {"t": round(idx * bucket_seconds, 2), "packets": 0, "bytes": 0}
            buckets[idx] = b
        b["packets"] += 1
        b["bytes"] += p.captured_length or 0
    series = [buckets[k] for k in sorted(buckets)]
    time_by_num = {p.packet_num: p.rel_time for p in packets}
    markers = []
    for a in alerts:
        nums = [n for n in a.related_packet_nums if n in time_by_num]
        if not nums:
            continue
        t0 = min(time_by_num[n] for n in nums)
        t1 = max(time_by_num[n] for n in nums)
        markers.append({
            "time": round(t0, 2), "end_time": round(t1, 2),
            "rule_id": a.rule_id, "title": a.title, "severity": a.severity,
            "mitre_id": a.mitre_technique_id, "src": a.source_ip, "dst": a.target_ip,
            "packet_count": len(nums),
        })
    return {"bucket_seconds": bucket_seconds, "series": series, "markers": markers}


# ---------------------------------------------------------------------------
# Inspection endpoints (mirrors inspect_packet / follow_stream / inspect_ip)
# ---------------------------------------------------------------------------

def inspect_packet(sess: AnalysisSession, packet_id: int) -> Dict[str, Any]:
    match = next((p for p in sess.all_packets if p.packet_num == packet_id), None)
    if not match:
        return {"found": False, "error": f"Packet #{packet_id} not found."}
    hex_dump = match.get_hex_dump()
    payload = match.raw_data[54:] if len(match.raw_data) > 54 else match.raw_data
    printable_lines = []
    for i in range(0, len(payload), 32):
        chunk = payload[i:i + 32]
        printable_lines.append("".join(chr(b) if 32 <= b <= 126 else "." for b in chunk))
    ascii_text = "\n".join(printable_lines) if printable_lines else "(No Application Payload)"
    entropy_res = PayloadDecoder.analyze_and_decode(payload) if len(payload) > 0 else {
        "Entropy": 0.0, "Is_High_Entropy": False, "Decodings": []
    }
    return {
        "found": True, "num": match.packet_num, "length": match.captured_length,
        "rel_time": f"{match.rel_time:.6f}", "src": match.src, "dst": match.dst,
        "src_port": match.src_port, "dst_port": match.dst_port,
        "protocol": match.protocol, "info": match.info, "layers": match.layers,
        "hex_dump": hex_dump, "ascii_text": ascii_text,
        "raw_payload_text": payload.decode("latin-1", errors="replace"),
        "entropy": entropy_res["Entropy"], "is_high_entropy": entropy_res["Is_High_Entropy"],
        "decodings": entropy_res["Decodings"],
    }


def follow_stream(sess: AnalysisSession, packet_id: int) -> Dict[str, Any]:
    match = next((p for p in sess.all_packets if p.packet_num == packet_id), None)
    if not match:
        return {"found": False, "error": f"Packet #{packet_id} not found."}
    res = StreamFollower.follow_stream_for_packet(match, sess.all_packets)
    return follow_stream_result(res)


def inspect_ip(sess: AnalysisSession, ip_address: str) -> Dict[str, Any]:
    geo = GeoResolverEngine.resolve_ip(ip_address)
    profile = None
    if sess.stream_profiler:
        profile = next((p for p in sess.stream_profiler.get_all_ip_profiles()
                        if p["IP"] == ip_address), None)
    if not profile:
        profile = {
            "IP": ip_address, "Total_Packets": 0, "Packets_Sent": 0, "Packets_Recv": 0,
            "Total_Bytes": 0, "Bytes_Sent": 0, "Bytes_Recv": 0, "Protocols": {},
            "Threat_Score": 0, "Threat_Level": "CLEAN", "Associated_Alerts": [],
        }
    score = profile.get("Threat_Score", 0)
    level = profile.get("Threat_Level", "CLEAN")
    if level == "MALICIOUS" or score >= 70:
        status, color = "DEFCON 1 (CRITICAL THREAT)", "#ef4444"
    elif level == "SUSPICIOUS" or score >= 40:
        status, color = "DEFCON 2 (ELEVATED RISK)", "#f97316"
    elif score >= 20:
        status, color = "DEFCON 3 (MODERATE RISK)", "#eab308"
    else:
        status, color = "DEFCON 5 (SYSTEMS NOMINAL)", "#10b981"

    peers: Dict[str, Dict[str, Any]] = {}
    ports: Dict[tuple, Dict[str, Any]] = {}
    for p in sess.all_packets:
        if p.src == ip_address or p.dst == ip_address:
            is_tx = p.src == ip_address
            peer_ip = p.dst if is_tx else p.src
            pe = peers.setdefault(peer_ip, {
                "peer": peer_ip, "packets_total": 0, "packets_tx": 0,
                "packets_rx": 0, "bytes_total": 0, "protocols": set(),
            })
            pe["packets_total"] += 1
            pe["packets_tx" if is_tx else "packets_rx"] += 1
            pe["bytes_total"] += p.captured_length
            pe["protocols"].add(p.protocol)
        if p.src == ip_address and p.dst_port:
            key = (p.dst_port, p.protocol, "Target Service (Outbound)")
            rec = ports.setdefault(key, {"port": p.dst_port, "protocol": p.protocol,
                                         "role": "Target Service (Outbound)", "count": 0})
            rec["count"] += 1
        if p.dst == ip_address and p.dst_port:
            key = (p.dst_port, p.protocol, "Listening Service (Inbound)")
            rec = ports.setdefault(key, {"port": p.dst_port, "protocol": p.protocol,
                                         "role": "Listening Service (Inbound)", "count": 0})
            rec["count"] += 1

    peers_list = sorted(
        [{"peer": k, **{kk: vv for kk, vv in v.items() if kk != "protocols"},
          "bytes_fmt": f"{v['bytes_total']:,} B", "protocols": sorted(v["protocols"])}
         for k, v in peers.items()],
        key=lambda x: x["packets_total"], reverse=True)
    port_footprint = sorted(ports.values(), key=lambda x: x["count"], reverse=True)

    threats_for_ip = []
    for a in sess.detected_alerts:
        if a.source_ip == ip_address or a.target_ip == ip_address:
            threats_for_ip.append({
                "rule_id": a.rule_id, "title": a.title, "severity": a.severity,
                "mitre_id": a.mitre_technique_id, "mitre_tactic": a.mitre_tactic,
                "role": "Threat Source (Attacker)" if a.source_ip == ip_address else "Threat Target (Victim)",
                "description": a.description, "packet_nums": a.related_packet_nums,
            })

    return {
        "ip": ip_address, "geo": geo, "profile": profile,
        "defcon": {"status": status, "color": color, "score": score, "level": level},
        "peers": peers_list, "port_footprint": port_footprint,
        "threats": threats_for_ip,
        "vt": get_intel_engine().lookup_ip_deep(ip_address),
        "carved": [cf.to_dict() for cf in sess.carved_files
                   if cf.source_ip == ip_address or cf.dest_ip == ip_address],
    }


def decode_raw(input_text: str, is_hex: bool) -> Dict[str, Any]:
    try:
        if is_hex:
            cleaned = "".join(c for c in input_text if c in "0123456789abcdefABCDEF")
            raw = bytes.fromhex(cleaned)
        else:
            raw = input_text.encode("latin-1", errors="replace")
        res = PayloadDecoder.analyze_and_decode(raw)
        return {"success": True, "entropy": res["Entropy"],
                "is_high_entropy": res["Is_High_Entropy"], "decodings": res["Decodings"]}
    except Exception as e:
        return {"success": False, "error": str(e)}


# ---------------------------------------------------------------------------
# Display-filter subset for /api/packets (Wireshark-like syntax)
# ---------------------------------------------------------------------------

def filter_packets(packets, query: Optional[str]):
    if not query or not query.strip():
        return packets
    q = query.strip().lower()
    tokens = q.split()
    def match(p: str) -> bool:
        for tok in tokens:
            if "==" in tok:
                field, _, val = tok.partition("==")
                field, val = field.strip(), val.strip()
                if field in ("ip.addr",):
                    if p.src != val and p.dst != val:
                        return False
                elif field == "ip.src":
                    if p.src != val:
                        return False
                elif field == "ip.dst":
                    if p.dst != val:
                        return False
                elif field in ("tcp.port", "udp.port", "port"):
                    if str(p.src_port) != val and str(p.dst_port) != val:
                        return False
                elif field in ("proto", "protocol"):
                    if p.protocol.lower() != val:
                        return False
                elif field == "frame.number":
                    if str(p.packet_num) != val:
                        return False
                else:
                    if val not in (p.info or "").lower():
                        return False
            else:
                hay = f"{p.src} {p.dst} {p.protocol} {p.info}".lower()
                if tok not in hay:
                    return False
        return True
    return [p for p in packets if match(p)]


# ---------------------------------------------------------------------------
# AI pipeline (mirrors run_ai_analysis, steps 1-13)
# ---------------------------------------------------------------------------

MATRIX_TACTICS = [
    {"name": "Initial Access", "sub": "TA0001", "techniques": [
        {"id": "T1190", "name": "Exploit Public App / SSRF"},
        {"id": "T1190", "name": "Exploit Public App / RCE"},
        {"id": "T1189", "name": "Drive-by Compromise / XSS"}]},
    {"name": "Execution", "sub": "TA0002", "techniques": [
        {"id": "T1059", "name": "Command Interpreter"},
        {"id": "T1203", "name": "Client Execution"}]},
    {"name": "Discovery", "sub": "TA0007", "techniques": [
        {"id": "T1046", "name": "Network Service Discovery"},
        {"id": "T1518", "name": "Software Discovery"}]},
    {"name": "Credential Access", "sub": "TA0006", "techniques": [
        {"id": "T1110.001", "name": "Password Guessing"},
        {"id": "T1552", "name": "Unsecured Creds"}]},
    {"name": "Command & Control", "sub": "TA0011", "techniques": [
        {"id": "T1071.001", "name": "Web Protocols"},
        {"id": "T1090", "name": "Proxy Multi-hop"}]},
    {"name": "Impact", "sub": "TA0040", "techniques": [
        {"id": "T1498.001", "name": "Direct Network Flood / SYN"},
        {"id": "T1498.002", "name": "Reflection Amplification"},
        {"id": "T1499.003", "name": "Application Exhaustion / Hulk"},
        {"id": "T1499.003", "name": "Slowloris / SlowHTTPTest"}]},
]


def run_ai(sess: AnalysisSession) -> Dict[str, Any]:
    if sess.ai_results:
        return sess.ai_results
    if not sess.all_packets:
        return {"has_data": False, "error": "No packets loaded to analyze."}

    import pandas as pd
    from ai_engine import AIFlowFeatureExtractor, AISentinelEngine, DFIRTelemetryEngine

    if sess.filepath and os.path.exists(sess.filepath):
        flows_df = AIFlowFeatureExtractor.parse_pcap_ultra_fast(sess.filepath)
    else:
        flows_df = AIFlowFeatureExtractor.extract_flows_from_packets(sess.all_packets)
    if flows_df is None or flows_df.empty:
        flows_df = AIFlowFeatureExtractor.extract_flows_from_packets(sess.all_packets)
    if flows_df.empty:
        return {"has_data": False, "error": "No IPv4/TCP/UDP flows extracted from capture."}

    engine = AISentinelEngine.get_instance()
    models = engine.load_models_lazy()
    aligned = AIFlowFeatureExtractor.align_columns(flows_df, models["expected_columns"])
    results = engine.run_ai_agent(flows_df, aligned)

    vt_key = ConfigManager.get_vt_api_key() or ""
    ip_summaries = engine.build_ip_summaries(results, flows_df, vt_api_key=vt_key)

    incidents = DFIRTelemetryEngine.build_correlation_incidents(flows_df, results)
    grounding_4q = DFIRTelemetryEngine.generate_4q_grounding(incidents, ip_summaries, flows_df)
    dns_telemetry = DFIRTelemetryEngine.analyze_dns_telemetry(sess.all_packets)
    tls_telemetry = DFIRTelemetryEngine.analyze_tls_telemetry(sess.all_packets)
    beaconing = DFIRTelemetryEngine.detect_c2_beaconing(sess.all_packets)

    counts = results["Final_Decision"].value_counts().to_dict()
    total_flows = len(results)
    attack_count = int(counts.get("Attack", 0))
    suspicious_count = int(counts.get("Suspicious", 0))
    normal_count = int(counts.get("Normal", 0))

    hierarchical_tree = []
    if ip_summaries:
        lead_ip = ip_summaries[0]["ip"]
        for _, r in flows_df[flows_df["src_ip"] == lead_ip].head(15).iterrows():
            proto_name = ("TCP" if r.get("protocol") == 6
                          else "UDP" if r.get("protocol") == 17 else "IP")
            hierarchical_tree.append({
                "src_ip": lead_ip, "dst_ip": str(r.get("dst_ip")),
                "dst_port": int(r.get("dst_port", 0)), "proto": proto_name,
                "status": "Malicious/Suspicious Flow",
            })

    active_mitre_tids = []
    for s in ip_summaries:
        tid = s.get("mitre", {}).get("technique_id")
        if tid and tid not in active_mitre_tids:
            active_mitre_tids.append(tid)

    evidence_hashes = DFIRTelemetryEngine.calculate_evidence_hashes(sess.filepath or b"")

    vector_map = {"attackers": [], "targets": [], "benign": [], "links": []}
    if not flows_df.empty:
        merged = flows_df.copy()
        merged["Final_Decision"] = results["Final_Decision"].values
        src_ips = list(merged["src_ip"].unique())
        dst_ips = list(merged["dst_ip"].unique())
        attacker_srcs = [ip for ip in src_ips
                         if merged[merged["src_ip"] == ip]["Final_Decision"].str.contains("Attack").any()]
        if not attacker_srcs and ip_summaries:
            attacker_srcs = [ip_summaries[0]["ip"]]
        benign_srcs = [ip for ip in src_ips if ip not in attacker_srcs]
        grouped = merged.groupby(["src_ip", "dst_ip", "Final_Decision"]).size().reset_index(name="count")
        links_data = [{"source": str(r["src_ip"]), "target": str(r["dst_ip"]),
                       "decision": str(r["Final_Decision"]), "count": int(r["count"])}
                      for _, r in grouped.head(40).iterrows()]
        vector_map = {"attackers": attacker_srcs[:5], "targets": dst_ips[:25],
                      "benign": benign_srcs[:8], "links": links_data}

    velocity_timeline = []
    if "timestamp" in flows_df.columns:
        try:
            t_df = flows_df.copy()
            t_df["Final_Decision"] = results["Final_Decision"].values
            t_df["dt"] = pd.to_datetime(t_df["timestamp"], errors="coerce")
            t_df = t_df.dropna(subset=["dt"]).sort_values("dt")
            if not t_df.empty:
                tg = (t_df.groupby([pd.Grouper(key="dt", freq="2s"), "Final_Decision"])
                      .size().unstack(fill_value=0).reset_index())
                for _, r in tg.head(45).iterrows():
                    velocity_timeline.append({
                        "time": r["dt"].strftime("%H:%M:%S"),
                        "attack": int(r.get("Attack", 0)),
                        "suspicious": int(r.get("Suspicious", 0)),
                        "normal": int(r.get("Normal", 0)),
                    })
        except Exception as e:
            print("[!] Velocity timeline error:", e)

    top_lead = ip_summaries[0] if ip_summaries else {}
    peak_val = (int(flows_df["flow_packets_s"].max())
                if ("flow_packets_s" in flows_df.columns and not flows_df.empty) else 18)
    soc_action_ar = f"تطبيق قواعد WAF لحظر {top_lead.get('ip', '192.168.100.5')} وعزل الجلسات النشطة فوراً."
    cti_summary = {
        "threat_ip": top_lead.get("ip", "192.168.100.5"),
        "vt_score": int(top_lead.get("intel", {}).get("score", 72)) if top_lead else 72,
        "severity": "CRITICAL" if attack_count > 0 else "NOMINAL",
        "mitre_tid": active_mitre_tids[0] if active_mitre_tids else "T1498",
        "tactic": top_lead.get("mitre", {}).get("tactic", "Impact"),
        "technique": top_lead.get("mitre", {}).get("technique_name", "Denial of Service"),
        "subtechnique": top_lead.get("mitre", {}).get("subtechnique", "Direct Network Flood"),
        "mitigation": "M1050 (Exploit Protection), Parameterized Queries / WAF / Border Rate-Limiting",
        "targets": top_lead.get("targets", ["192.168.0.4"]),
        "time_window": f"{top_lead.get('start_time', 'N/A')} → {top_lead.get('end_time', 'N/A')}",
        "peak_rate": f"{peak_val:,} Pkts/s",
        "soc_action": soc_action_ar,
        "firewall_cmd": top_lead.get("firewall_command",
                                     f"iptables -A INPUT -s {top_lead.get('ip', '192.168.100.5')} -j DROP"),
    }

    # Anomaly score histogram for the dashboard AI panel (new aggregate)
    anomaly_hist = []
    try:
        import math
        scores = [s for s in results["Anomaly_Score"].tolist() if isinstance(s, (int, float)) and not math.isnan(s)]
        bins = 20
        if scores:
            lo, hi = min(scores), max(scores)
            width = (hi - lo) / bins if hi > lo else 1.0
            counts_b = [0] * bins
            for s in scores:
                k = min(int((s - lo) / width), bins - 1)
                counts_b[k] += 1
            anomaly_hist = [{"bin": round(lo + i * width, 4), "count": counts_b[i]} for i in range(bins)]
    except Exception as e:
        print("[!] Anomaly histogram error:", e)

    sess.ai_results = {
        "has_data": True,
        "total_flows": total_flows,
        "attack_count": attack_count,
        "suspicious_count": suspicious_count,
        "normal_count": normal_count,
        "attack_pct": round((attack_count / total_flows) * 100, 1) if total_flows > 0 else 0,
        "ip_summaries": ip_summaries,
        "grounding_4q": grounding_4q,
        "incidents": incidents,
        "dns_telemetry": dns_telemetry,
        "tls_telemetry": tls_telemetry,
        "beaconing": beaconing,
        "hierarchical_tree": hierarchical_tree,
        "active_mitre_tids": active_mitre_tids,
        "evidence_hashes": evidence_hashes,
        "vector_map": vector_map,
        "velocity_timeline": velocity_timeline,
        "matrix_tactics": MATRIX_TACTICS,
        "cti_summary": cti_summary,
        "anomaly_hist": anomaly_hist,
        "presets": DFIRTelemetryEngine.get_preset_scenarios(),
    }
    return sess.ai_results
