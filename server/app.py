"""
FastAPI Server & WebSocket Telemetry Streamer for ShadowHarness Cockpit.
"""

import asyncio
import json
import os
from typing import Set, Dict, Any, Optional
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from fastapi.responses import FileResponse
from pydantic import BaseModel

from shadowharness import ShadowHarness, OpenClawAdapter, DeepSeekHarnessAdapter
from agent import AutonomousAgent, SCENARIOS

app = FastAPI(title="ShadowHarness Security Cockpit")

# Active WebSocket connections
active_connections: Set[WebSocket] = set()

# Base directory paths
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
FRONTEND_DIR = os.path.join(BASE_DIR, "frontend")


class RunRequest(BaseModel):
    scenario_id: str
    protected: bool = True
    delay: float = 0.6


@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        # Send initial status
        await websocket.send_json({
            "event": "CONNECTED",
            "data": {"status": "Cockpit Connected to ShadowHarness Core Engine"}
        })
        while True:
            # Keep-alive
            data = await websocket.receive_text()
    except WebSocketDisconnect:
        active_connections.remove(websocket)


async def broadcast_event(event_type: str, payload: Dict[str, Any]):
    """Broadcasts a telemetry event to all connected UI clients."""
    if not active_connections:
        return
    message = json.dumps({"event": event_type, "data": payload})
    disconnected = set()
    for ws in active_connections:
        try:
            await ws.send_text(message)
        except Exception:
            disconnected.add(ws)
    for ws in disconnected:
        active_connections.discard(ws)


latest_harness: Optional[ShadowHarness] = None


@app.get("/api/scenarios")
def get_scenarios():
    return SCENARIOS


@app.get("/api/forensics")
def get_forensics():
    """Returns the forensic incident audit records."""
    if latest_harness:
        return latest_harness.export_forensics()
    return []


@app.get("/api/checkpoints")
def get_checkpoints():
    """Returns all captured checkpoint frames."""
    if latest_harness:
        return [chk.model_dump() for chk in latest_harness.checkpointer.checkpoints]
    return []


@app.get("/api/checkpoints/diff")
def diff_checkpoints(a: str, b: str):
    """Computes a structural state diff between two checkpoints."""
    if not latest_harness:
        return {"error": "No active harness session available."}
    try:
        return latest_harness.checkpointer.diff_checkpoints(a, b)
    except Exception as e:
        return {"error": str(e)}


@app.post("/api/run")
async def run_scenario_endpoint(req: RunRequest):
    """Executes a scenario and streams events over WebSockets."""
    global latest_harness
    loop = asyncio.get_running_loop()

    # Create harness with async event bridge and multi-framework adapters
    latest_harness = ShadowHarness()
    OpenClawAdapter(latest_harness)
    DeepSeekHarnessAdapter(latest_harness)

    def sync_listener(event_type: str, payload: Dict[str, Any]):
        # Schedule the async broadcast on the running event loop
        asyncio.run_coroutine_threadsafe(
            broadcast_event(event_type, payload),
            loop
        )

    latest_harness.add_event_listener(sync_listener)
    agent = AutonomousAgent(harness=latest_harness, protected=req.protected)

    # Run in background executor so it doesn't block FastAPI
    result = await loop.run_in_executor(
        None,
        lambda: agent.run_scenario(req.scenario_id, delay_seconds=req.delay)
    )

    return {
        "status": "finished",
        "result": result,
        "forensics": latest_harness.export_forensics()
    }


# Mount frontend static files
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")


@app.get("/")
def serve_index():
    index_path = os.path.join(FRONTEND_DIR, "index.html")
    if os.path.exists(index_path):
        return FileResponse(index_path)
    return {"message": "ShadowHarness API running. Frontend index.html not found."}
