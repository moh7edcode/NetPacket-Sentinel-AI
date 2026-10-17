"""FastAPI entrypoint wrapping the NetPacket-Sentinel-AI engine.

Run: uvicorn backend.main:app --reload --port 8000
"""
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)  # engine modules live at repo root

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api import router as api_router
from backend.ws import router as ws_router

app = FastAPI(title="NetPacket-Sentinel-AI API", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)
app.include_router(ws_router)


@app.get("/api/health")
def health():
    return {"status": "ok", "engines": ["pcap_parser", "analyzer", "threat_detector",
                                        "ai_engine", "stream_follower", "file_carver",
                                        "payload_decoder", "threat_intel", "geo_resolver",
                                        "network_attacks_catalog", "ai_triage_playbook",
                                        "exporter", "dashboard_generator", "stream_profiler"]}
