"""Job/session registry mirroring the state CyberBridgeAPI held between calls."""
import os
import threading
import uuid
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class Job:
    id: str
    filepath: str
    filename: str
    status: str = "pending"  # pending | running | done | error
    error: Optional[str] = None
    progress: List[Dict[str, Any]] = field(default_factory=list)
    lock: threading.Lock = field(default_factory=threading.Lock)

    def emit(self, stage: str, pct: float, label: str):
        with self.lock:
            self.progress.append({"stage": stage, "pct": pct, "label": label})

    def snapshot(self) -> Dict[str, Any]:
        with self.lock:
            return {
                "job_id": self.id,
                "filename": self.filename,
                "status": self.status,
                "error": self.error,
                "progress": list(self.progress),
            }


class AnalysisSession:
    """Holds the full forensic dataset for one analyzed capture."""

    def __init__(self, job: Job):
        self.job = job
        self.filepath = job.filepath
        self.filename = job.filename
        self.all_packets: List[Any] = []
        self.detected_alerts: List[Any] = []
        self.stream_profiler = None
        self.catalog_results: List[Any] = []
        self.geo_results: List[Dict[str, Any]] = []
        self.carved_files: List[Any] = []
        self.attack_timeline: List[Dict[str, Any]] = []
        self.soc_playbook: List[Dict[str, Any]] = []
        self.payload: Optional[Dict[str, Any]] = None      # cached_payload equivalent
        self.ai_results: Optional[Dict[str, Any]] = None   # cached_ai_results equivalent
        self.timeline_series: Optional[Dict[str, Any]] = None

    def invalidate_ai(self):
        self.ai_results = None


class SessionManager:
    def __init__(self):
        self._lock = threading.Lock()
        self.jobs: Dict[str, Job] = {}
        self.sessions: Dict[str, AnalysisSession] = {}
        self.active_job_id: Optional[str] = None

    def create_job(self, filepath: str, filename: str) -> Job:
        job = Job(id=uuid.uuid4().hex[:12], filepath=filepath, filename=filename)
        with self._lock:
            self.jobs[job.id] = job
            self.sessions[job.id] = AnalysisSession(job)
        return job

    def get_job(self, job_id: str) -> Optional[Job]:
        return self.jobs.get(job_id)

    def get_session(self, job_id: Optional[str] = None) -> Optional[AnalysisSession]:
        with self._lock:
            jid = job_id or self.active_job_id
            if not jid:
                return None
            return self.sessions.get(jid)

    def set_active(self, job_id: str):
        with self._lock:
            self.active_job_id = job_id

    def active_session(self) -> Optional[AnalysisSession]:
        return self.get_session()

    def clear_old_uploads(self, keep: int = 10):
        """Keep upload dir bounded: remove oldest finished job files beyond `keep`."""
        with self._lock:
            finished = [j for j in self.jobs.values() if j.status in ("done", "error")]
        for j in finished[:-keep] if keep else []:
            try:
                if os.path.exists(j.filepath):
                    os.remove(j.filepath)
            except OSError:
                pass


manager = SessionManager()
