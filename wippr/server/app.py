"""
FastAPI Server & WebSocket Telemetry Streamer for the wippr cockpit.
"""

import asyncio
import json
import os
from typing import Set, Dict, Any, Optional

import hmac
import secrets

from fastapi import Depends, FastAPI, Header, HTTPException, WebSocket, WebSocketDisconnect
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from wippr import __version__, WipprHarness, OpenClawAdapter, DeepSeekHarnessAdapter
from wippr.demo import AutonomousAgent, SCENARIOS

WEB_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "web")

app = FastAPI(title="wippr cockpit", version=__version__, docs_url="/api/docs", redoc_url=None)

active_connections: Set[WebSocket] = set()
latest_harness: Optional[WipprHarness] = None
run_lock = asyncio.Lock()


class RunRequest(BaseModel):
    scenario_id: str
    protected: bool = True
    delay: float = Field(default=0.6, ge=0.0, le=3.0)


@app.websocket("/ws/telemetry")
async def websocket_endpoint(websocket: WebSocket):
    await websocket.accept()
    active_connections.add(websocket)
    try:
        await websocket.send_json({
            "event": "CONNECTED",
            "data": {"status": "Cockpit connected to wippr engine", "version": __version__}
        })
        while True:
            await websocket.receive_text()  # keep-alive; client messages are ignored
    except WebSocketDisconnect:
        pass
    finally:
        active_connections.discard(websocket)


async def broadcast_event(event_type: str, payload: Dict[str, Any]):
    """Broadcasts a telemetry event to all connected UI clients."""
    if not active_connections:
        return
    message = json.dumps({"event": event_type, "data": payload}, default=str)
    for ws in list(active_connections):
        try:
            await ws.send_text(message)
        except Exception:
            active_connections.discard(ws)


@app.get("/api/health")
def health():
    return {"status": "ok", "version": __version__, "busy": run_lock.locked()}


@app.get("/api/scenarios")
def get_scenarios():
    return SCENARIOS


@app.get("/api/forensics")
def get_forensics():
    """Returns the forensic incident audit records of the latest run."""
    return latest_harness.export_forensics() if latest_harness else []


@app.get("/api/checkpoints")
def get_checkpoints():
    """Returns all checkpoint frames captured in the latest run."""
    if not latest_harness:
        return []
    return [chk.model_dump() for chk in latest_harness.checkpointer.checkpoints]


@app.get("/api/checkpoints/diff")
def diff_checkpoints(a: str, b: str):
    """Computes a structural state diff between two checkpoints."""
    if not latest_harness:
        raise HTTPException(status_code=404, detail="No run has been executed yet.")
    try:
        return latest_harness.checkpointer.diff_checkpoints(a, b)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.post("/api/run")
async def run_scenario_endpoint(req: RunRequest):
    """Executes a scenario and streams its events over WebSockets. One run at a time."""
    global latest_harness
    if req.scenario_id not in SCENARIOS:
        raise HTTPException(status_code=404, detail=f"Unknown scenario '{req.scenario_id}'.")
    if run_lock.locked():
        raise HTTPException(status_code=409, detail="A scenario is already running. Try again when it finishes.")

    async with run_lock:
        loop = asyncio.get_running_loop()
        harness = WipprHarness()
        OpenClawAdapter(harness)
        DeepSeekHarnessAdapter(harness)

        def sync_listener(event_type: str, payload: Dict[str, Any]):
            asyncio.run_coroutine_threadsafe(broadcast_event(event_type, payload), loop)

        harness.add_event_listener(sync_listener)
        latest_harness = harness
        agent = AutonomousAgent(harness=harness, protected=req.protected)

        try:
            result = await loop.run_in_executor(
                None, lambda: agent.run_scenario(req.scenario_id, delay_seconds=req.delay)
            )
        except Exception as e:
            await broadcast_event("RUN_ERROR", {"error": str(e)})
            raise HTTPException(status_code=500, detail=f"Scenario failed: {e}")

        await broadcast_event("RUN_FINISHED", {"status": result.get("status")})
        return {
            "status": "finished",
            "result": result,
            "forensics": harness.export_forensics()
        }


# ── /v1: gate API for real agents ────────────────────────────────────────────

def gate_token() -> str:
    """Token for /v1 calls: WIPPR_TOKEN, else ~/.wippr/token (created with 0600 on first use)."""
    from wippr.store import wippr_home
    env = os.environ.get("WIPPR_TOKEN")
    if env:
        return env
    path = os.path.join(wippr_home(), "token")
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), mode=0o700, exist_ok=True)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(secrets.token_urlsafe(32))
    with open(path) as fh:
        return fh.read().strip()


def require_token(authorization: Optional[str] = Header(default=None)) -> None:
    expected = gate_token()
    supplied = (authorization or "").removeprefix("Bearer ").strip()
    if not supplied or not hmac.compare_digest(supplied, expected):
        raise HTTPException(status_code=401, detail="Missing or invalid bearer token (see ~/.wippr/token).")


_runtime = None


def runtime():
    global _runtime
    if _runtime is None:
        from wippr.runtime import GuardRuntime
        _runtime = GuardRuntime()
    return _runtime


class GateRequest(BaseModel):
    session: str = "default"
    tool: str
    params: Dict[str, Any] = Field(default_factory=dict)
    goal: Optional[str] = None
    requester: Optional[Dict[str, Any]] = None


class IngestRequest(BaseModel):
    session: str = "default"
    source: str = "external"
    content: str
    trusted: bool = False
    channel: Optional[str] = None
    sender: Optional[str] = None


class CheckpointRequest(BaseModel):
    session: str = "default"
    messages: list = Field(default_factory=list)
    scratchpad: list = Field(default_factory=list)
    goal: Optional[str] = None


@app.post("/v1/gate", dependencies=[Depends(require_token)])
def v1_gate(req: GateRequest):
    return runtime().gate(req.session, req.tool, req.params, goal=req.goal, requester=req.requester).to_dict()


@app.post("/v1/ingest", dependencies=[Depends(require_token)])
def v1_ingest(req: IngestRequest):
    return runtime().ingest(req.session, req.source, req.content, trusted=req.trusted, channel=req.channel, sender=req.sender)


@app.post("/v1/hook", dependencies=[Depends(require_token)])
def v1_hook(payload: Dict[str, Any]):
    """Same contract as `wippr hook --format openclaw`, for the OpenClaw plugin's gateUrl mode."""
    from wippr.cli_runtime import _hook_openclaw
    from wippr.runtime import GuardRuntime
    rt = GuardRuntime(store=runtime().store, monitor=True) if payload.get("monitor") else runtime()
    try:
        return _hook_openclaw(rt, payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@app.post("/v1/checkpoint", dependencies=[Depends(require_token)])
def v1_checkpoint(req: CheckpointRequest):
    return runtime().checkpoint(req.session, messages=req.messages, scratchpad=req.scratchpad, goal=req.goal).model_dump()


@app.post("/v1/sessions/{session}/rollback", dependencies=[Depends(require_token)])
def v1_rollback(session: str, checkpoint_id: Optional[str] = None):
    try:
        return runtime().rollback(session, checkpoint_id).model_dump()
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))


@app.get("/v1/sessions", dependencies=[Depends(require_token)])
def v1_sessions():
    return runtime().store.sessions()


@app.get("/v1/sessions/{session}", dependencies=[Depends(require_token)])
def v1_session(session: str):
    return runtime().status(session)


@app.delete("/v1/sessions/{session}", dependencies=[Depends(require_token)])
def v1_reset(session: str):
    runtime().reset(session)
    return {"session": session, "reset": True}


@app.get("/v1/incidents", dependencies=[Depends(require_token)])
def v1_incidents(session: Optional[str] = None, limit: int = 50):
    return runtime().store.incidents(session, limit=min(max(limit, 1), 500))


# Web UI is served last so API routes take precedence
if os.path.isdir(WEB_DIR):
    app.mount("/", StaticFiles(directory=WEB_DIR, html=True), name="web")
