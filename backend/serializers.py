"""JSON-safe serialization for engine objects holding bytes / class instances."""
from typing import Any, Dict, List


def stream_chunk_to_dict(c) -> Dict[str, Any]:
    return {
        "direction": c.direction,
        "sender": c.sender_endpoint,
        "receiver": c.receiver_endpoint,
        "packet_num": c.packet_num,
        "rel_time": f"{c.rel_time:.6f}",
        "text": c.text,
        "hex": c.data.hex() if c.data else "",
    }


def follow_stream_result(res: Dict[str, Any]) -> Dict[str, Any]:
    chunks = [stream_chunk_to_dict(c) for c in res.get("Chunks", [])]
    return {
        "found": res.get("Stream_Found", False),
        "protocol": res.get("Protocol", "TCP"),
        "client": res.get("Client", ""),
        "server": res.get("Server", ""),
        "total_packets": res.get("Total_Packets", 0),
        "duration": res.get("Duration_Seconds", 0.0),
        "client_bytes": res.get("Client_Bytes", 0),
        "server_bytes": res.get("Server_Bytes", 0),
        "chunks_count": len(chunks),
        "chunks": chunks,
    }


def packet_summary(p) -> Dict[str, Any]:
    return {
        "num": p.packet_num,
        "time": f"{p.rel_time:.6f}",
        "src": p.src,
        "dst": p.dst,
        "src_port": p.src_port,
        "dst_port": p.dst_port,
        "proto": p.protocol,
        "protocol": p.protocol,
        "length": p.captured_length,
        "info": p.info,
    }


def catalog_results_to_list(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    for idx, res in enumerate(results):
        atk = res["Definition"]
        out.append({
            "id": idx,
            "attack_id": atk.attack_id,
            "name_en": atk.name_en,
            "name_ar": atk.name_ar,
            "severity": atk.severity,
            "mitre_id": atk.mitre_id,
            "mitre_tactic": atk.mitre_tactic,
            "category": atk.category,
            "detected": bool(res["Is_Detected"]),
            "matched_packets_count": res["Matched_Packets_Count"],
            "matched_packets": res["Matched_Packet_Numbers"],
            "mechanism": atk.mechanism_explanation,
            "mitigation": atk.mitigation,
            "rules": atk.detection_rules,
            "evidence": str(res.get("Evidence") or ""),
        })
    return out


def alerts_to_list(alerts) -> List[Dict[str, Any]]:
    out = []
    for idx, a in enumerate(alerts):
        out.append({
            "id": idx,
            "rule_id": a.rule_id,
            "title": a.title,
            "severity": a.severity,
            "mitre_id": a.mitre_technique_id,
            "mitre_tactic": a.mitre_tactic,
            "src": a.source_ip,
            "dst": a.target_ip,
            "packet_count": len(a.related_packet_nums),
            "packet_nums": a.related_packet_nums,
            "description": a.description,
            "evidence": a.evidence,
        })
    return out
