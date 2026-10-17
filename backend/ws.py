"""WebSocket live analysis progress. The pipeline thread records stage events on
the Job; the socket streams them until the job finishes."""
import asyncio

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.sessions import manager

router = APIRouter()


@router.websocket("/ws/progress/{job_id}")
async def progress_ws(ws: WebSocket, job_id: str):
    await ws.accept()
    try:
        sent = 0
        while True:
            job = manager.get_job(job_id)
            if job is None:
                await ws.send_json({"type": "error", "error": f"Unknown job {job_id}"})
                break
            snap = job.snapshot()
            events = snap["progress"][sent:]
            for ev in events:
                await ws.send_json({"type": "progress", "job_id": job_id, **ev})
            sent = len(snap["progress"])
            if snap["status"] in ("done", "error"):
                await ws.send_json({
                    "type": "complete", "job_id": job_id,
                    "status": snap["status"], "error": snap["error"],
                })
                break
            await asyncio.sleep(0.3)
    except (WebSocketDisconnect, RuntimeError):
        pass
