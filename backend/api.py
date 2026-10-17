"""REST API — one endpoint per CyberBridgeAPI method (see ARCHITECTURE.md table)."""
import os
import threading
import uuid
from typing import Any, Dict, Optional

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from fastapi.responses import FileResponse, Response
from pydantic import BaseModel

from backend import pipeline
from backend.serializers import packet_summary
from backend.sessions import AnalysisSession, Job, manager

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
UPLOAD_DIR = os.path.join(ROOT, "backend", "uploads")
EXPORT_DIR = os.path.join(ROOT, "backend", "exports")
os.makedirs(UPLOAD_DIR, exist_ok=True)
os.makedirs(EXPORT_DIR, exist_ok=True)

router = APIRouter(prefix="/api")


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def require_session(job: Optional[str] = None) -> AnalysisSession:
    sess = manager.get_session(job)
    if sess is None or not sess.all_packets:
        raise HTTPException(status_code=409, detail="No capture analyzed yet. Upload a PCAP first.")
    return sess


def start_job(filepath: str, filename: str) -> str:
    job = manager.create_job(filepath, filename)

    def runner():
        job.status = "running"
        try:
            pipeline.run_full_pipeline(job, manager.sessions[job.id])
            job.status = "done"
            manager.set_active(job.id)
        except Exception as e:
            import traceback
            traceback.print_exc()
            job.status = "error"
            job.error = str(e)
            job.emit("error", 100, str(e))
        manager.clear_old_uploads()

    threading.Thread(target=runner, daemon=True).start()
    return job.id


# ---------------------------------------------------------------------------
# ingest (bridge: open_file_dialog / load_pcap / load_preset_scenario)
# ---------------------------------------------------------------------------

class LocalPath(BaseModel):
    path: str


@router.post("/pcap/upload")
async def pcap_upload(file: UploadFile = File(...)):
    if not file.filename or not file.filename.lower().endswith((".pcap", ".pcapng")):
        raise HTTPException(status_code=400, detail="Upload must be a .pcap or .pcapng file.")
    safe = f"{uuid.uuid4().hex[:8]}_{os.path.basename(file.filename)}"
    dest = os.path.join(UPLOAD_DIR, safe)
    with open(dest, "wb") as f:
        f.write(await file.read())
    return {"job_id": start_job(dest, file.filename)}


@router.post("/pcap/local")
def pcap_local(body: LocalPath):
    p = os.path.abspath(body.path)
    if not os.path.isfile(p):
        raise HTTPException(status_code=404, detail=f"File not found: {p}")
    return {"job_id": start_job(p, os.path.basename(p))}


@router.get("/jobs/{job_id}")
def job_status(job_id: str):
    job = manager.get_job(job_id)
    if job is None:
        raise HTTPException(status_code=404, detail="Unknown job")
    return job.snapshot()


@router.get("/session")
def session_state():
    sess = manager.active_session()
    if sess is None or sess.payload is None:
        return {"has_data": False, "message": "No capture loaded."}
    return {"has_data": True, **sess.job.snapshot()}


# ---------------------------------------------------------------------------
# core payload sections (bridge: get_initial_data)
# ---------------------------------------------------------------------------

def _payload(sess: AnalysisSession, drop=()):
    out = {k: v for k, v in sess.payload.items() if k not in drop}
    return out


@router.get("/summary")
def summary(job: Optional[str] = None):
    return _payload(require_session(job), drop=("filepath",))


@router.get("/hud")
def hud(job: Optional[str] = None):
    return require_session(job).payload["hud"]


@router.get("/protocol-distribution")
def protocol_distribution(job: Optional[str] = None):
    return {"protocol_dist": require_session(job).payload["protocol_dist"],
            "summary_stats": require_session(job).payload["summary_stats"]}


@router.get("/packets")
def packets(offset: int = 0, limit: int = 500, q: Optional[str] = None,
            job: Optional[str] = None):
    sess = require_session(job)
    subset = pipeline.filter_packets(sess.all_packets, q)
    batch = subset[offset:offset + min(limit, 5000)]
    return {"total_packets": len(subset), "offset": offset, "limit": limit,
            "query": q or "", "packets": [packet_summary(p) for p in batch]}


@router.get("/packets/{num}")
def packet_detail(num: int, job: Optional[str] = None):
    return pipeline.inspect_packet(require_session(job), num)


@router.get("/streams/follow/{num}")
def stream_follow(num: int, job: Optional[str] = None):
    return pipeline.follow_stream(require_session(job), num)


@router.get("/ip/{ip}")
def ip_inspect(ip: str, job: Optional[str] = None):
    return pipeline.inspect_ip(require_session(job), ip)


@router.get("/timeline/series")
def timeline_series(job: Optional[str] = None):
    sess = require_session(job)
    return sess.timeline_series or {"series": [], "markers": []}


# per-section passthroughs so pages fetch only what they need
for _key, _name in [("threats", "threats"), ("topology", "topology"),
                    ("catalog", "catalog"), ("geo", "geo"), ("carved", "carved"),
                    ("timeline", "timeline"), ("playbook", "playbook"),
                    ("ip_profiles", "ip-profiles"), ("streams", "streams-list"),
                    ("defcon", "defcon")]:
    def _make(k=_key, n=_name):
        @router.get(f"/{n}", name=n)
        def _ep(job: Optional[str] = None, _k=k):
            sess = require_session(job)
            v = sess.payload.get(_k, [])
            return v if isinstance(v, (list, dict)) else {n: v}
    _make()


# ---------------------------------------------------------------------------
# threat intel & config (bridge: lookup_vt_deep / save_vt_key / get_vt_key)
# ---------------------------------------------------------------------------

@router.get("/intel/{target}")
def intel_lookup(target: str, kind: str = Query("ip", pattern="^(ip|domain)$")):
    eng = pipeline.get_intel_engine()
    return (eng.lookup_ip_deep(target) if kind == "ip"
            else eng.lookup_domain_deep(target))


class VtKey(BaseModel):
    api_key: str


@router.get("/config/vt-key")
def vt_key_get():
    from config_manager import ConfigManager
    return {"api_key": ConfigManager.get_vt_api_key() or ""}


@router.put("/config/vt-key")
def vt_key_put(body: VtKey):
    from config_manager import ConfigManager
    key = body.api_key.strip()
    ConfigManager.set_vt_api_key(key)
    pipeline.reset_intel_engine(key if key else None)
    return {"success": True, "message": "VirusTotal API key persisted successfully."}


# ---------------------------------------------------------------------------
# payload decoder sandbox (bridge: decode_payload_raw)
# ---------------------------------------------------------------------------

class DecodeIn(BaseModel):
    input_text: str
    is_hex: bool = False


@router.post("/decoder")
def decoder(body: DecodeIn):
    return pipeline.decode_raw(body.input_text, body.is_hex)


# ---------------------------------------------------------------------------
# AI (bridge: run_ai_analysis / get_ai_data / simulate_sandbox /
#        get_ai_benchmarks / get_preset_scenarios / load_preset_scenario)
# ---------------------------------------------------------------------------

@router.get("/ai")
def ai(job: Optional[str] = None):
    sess = require_session(job)
    try:
        return pipeline.run_ai(sess)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return {"has_data": False, "error": str(e)}


class SandboxIn(BaseModel):
    params: Dict[str, Any]


@router.post("/ai/sandbox")
def ai_sandbox(body: SandboxIn):
    from ai_engine import AISentinelEngine
    try:
        return AISentinelEngine.get_instance().simulate_sandbox(body.params)
    except Exception as e:
        return {"error": str(e)}


@router.get("/ai/benchmarks")
def ai_benchmarks():
    from ai_engine import AISentinelEngine
    return {"benchmark": AISentinelEngine.get_model_benchmark_data(),
            "viva_guide": AISentinelEngine.get_viva_defense_guide()}


@router.get("/ai/presets")
def ai_presets():
    from ai_engine import DFIRTelemetryEngine
    return {"presets": DFIRTelemetryEngine.get_preset_scenarios()}


@router.post("/ai/presets/{scenario_id}/load")
def ai_preset_load(scenario_id: str):
    from ai_engine import DFIRTelemetryEngine
    target = next((p for p in DFIRTelemetryEngine.get_preset_scenarios()
                   if p["id"] == scenario_id), None)
    if not target or not os.path.exists(target.get("full_path", "")):
        raise HTTPException(status_code=404, detail=f"Scenario '{scenario_id}' not found.")
    return {"job_id": start_job(target["full_path"], os.path.basename(target["full_path"]))}


# ---------------------------------------------------------------------------
# carved file download (bridge: save_carved_file)
# ---------------------------------------------------------------------------

@router.get("/carved/{file_id}/download")
def carved_download(file_id: int, job: Optional[str] = None):
    sess = require_session(job)
    cf = next((f for f in sess.carved_files if f.file_id == file_id), None)
    if cf is None:
        raise HTTPException(status_code=404, detail=f"Carved file ID {file_id} not found.")
    return Response(content=cf.content, media_type="application/octet-stream",
                    headers={"Content-Disposition": f'attachment; filename="{cf.filename}"'})


# ---------------------------------------------------------------------------
# reports (bridge: export_report / open_external_dashboard)
# ---------------------------------------------------------------------------

class ReportIn(BaseModel):
    format: str  # html | json | csv | dashboard


@router.post("/report/generate")
def report_generate(body: ReportIn, job: Optional[str] = None):
    sess = require_session(job)
    fmt = body.format.lower()
    from config_manager import ConfigManager
    from exporter import PacketExporter
    vt_key = ConfigManager.get_vt_api_key()
    base = os.path.splitext(os.path.basename(sess.filepath))[0]

    if fmt == "dashboard":
        from dashboard_generator import DashboardGenerator
        out = os.path.join(EXPORT_DIR, f"{base}_dashboard.html")
        DashboardGenerator.generate_dashboard(sess.all_packets, out,
                                              source_filename=sess.filename, vt_api_key=vt_key)
        return {"success": True, "format": fmt, "filename": os.path.basename(out),
                "download_url": f"/api/report/download/{os.path.basename(out)}"}
    if fmt == "html":
        out = os.path.join(EXPORT_DIR, f"{base}_forensic_report.html")
        PacketExporter.export_html_report(sess.all_packets, out, sess.filename, vt_api_key=vt_key)
    elif fmt == "json":
        out = os.path.join(EXPORT_DIR, f"{base}_forensic_report.json")
        PacketExporter.export_json(sess.all_packets, out, sess.detected_alerts)
    elif fmt == "csv":
        out = os.path.join(EXPORT_DIR, f"{base}_forensic_report.csv")
        PacketExporter.export_csv(sess.all_packets, out)
    else:
        raise HTTPException(status_code=400, detail="format must be html|json|csv|dashboard")
    return {"success": True, "format": fmt, "filename": os.path.basename(out),
            "download_url": f"/api/report/download/{os.path.basename(out)}"}


@router.get("/report/download/{name}")
def report_download(name: str):
    safe = os.path.basename(name)
    path = os.path.join(EXPORT_DIR, safe)
    if not os.path.isfile(path):
        raise HTTPException(status_code=404, detail="Report not found.")
    return FileResponse(path, filename=safe)


# ---------------------------------------------------------------------------
# blocklist / containment (bridge: export_containment_script)
# ---------------------------------------------------------------------------

class BlocklistIn(BaseModel):
    attacker_ip: str
    attack_type: str = "Hostile Intrusion"
    mitre_id: str = "T1498"


@router.post("/blocklist/generate")
def blocklist_generate(body: BlocklistIn):
    from ai_engine import DFIRTelemetryEngine
    pb = DFIRTelemetryEngine.generate_containment_playbook(
        body.attacker_ip, body.attack_type, body.mitre_id)
    script = pb.get("playbook_script", "") if isinstance(pb, dict) else str(pb)
    out = os.path.join(EXPORT_DIR, f"contain_{body.attacker_ip.replace('.', '_')}.sh")
    with open(out, "w", encoding="utf-8", newline="\n") as f:
        f.write(script)
    return {"success": True, "playbook": pb,
            "download_url": f"/api/report/download/{os.path.basename(out)}"}
