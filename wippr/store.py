"""
Persistent state for real agent sessions: taint records, gate decisions, incidents.

One SQLite database (WAL mode) is shared by every process — the CLI hook that
OpenClaw spawns per tool call, `wippr serve`, and the Python API — so taint
recorded by one call is visible to the next.
"""

import json
import os
import sqlite3
import time
import uuid
from contextlib import contextmanager
from typing import Any, Dict, Iterator, List, Optional

from .models import TaintRecord


def wippr_home() -> str:
    return os.path.expanduser(os.environ.get("WIPPR_HOME", "~/.wippr"))


def default_db_path() -> str:
    return os.environ.get("WIPPR_DB") or os.path.join(wippr_home(), "wippr.db")


SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    id TEXT PRIMARY KEY,
    goal TEXT,
    created REAL NOT NULL,
    updated REAL NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}'
);
CREATE TABLE IF NOT EXISTS taints (
    id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    source TEXT NOT NULL,
    level TEXT NOT NULL,
    markers TEXT NOT NULL,
    snippet TEXT NOT NULL,
    meta TEXT NOT NULL DEFAULT '{}',
    created REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_taints_session ON taints(session, created);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    session TEXT NOT NULL,
    created REAL NOT NULL,
    type TEXT NOT NULL,
    tool TEXT,
    kind TEXT,
    action TEXT,
    rule TEXT,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session, created);
CREATE TABLE IF NOT EXISTS incidents (
    id TEXT PRIMARY KEY,
    session TEXT NOT NULL,
    created REAL NOT NULL,
    tool TEXT NOT NULL,
    kind TEXT,
    action TEXT NOT NULL,
    rule TEXT,
    reason TEXT NOT NULL,
    params TEXT NOT NULL,
    findings TEXT NOT NULL,
    requester TEXT,
    source_chain TEXT,
    quarantine_id TEXT,
    restored_checkpoint TEXT,
    latency_ms REAL
);
CREATE INDEX IF NOT EXISTS idx_incidents_session ON incidents(session, created);
"""


class Store:
    def __init__(self, path: Optional[str] = None):
        self.path = path or default_db_path()
        if self.path == ":memory:":
            raise ValueError("Store needs a file path: state is shared across processes.")
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), mode=0o700, exist_ok=True)
        with self._conn() as c:
            c.executescript(SCHEMA)
        try:
            os.chmod(self.path, 0o600)  # holds snippets of untrusted content and tool arguments
        except OSError:
            pass

    @contextmanager
    def _conn(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(self.path, timeout=10)
        conn.row_factory = sqlite3.Row
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            yield conn
            conn.commit()
        finally:
            conn.close()

    # sessions -----------------------------------------------------------------
    def touch_session(self, session: str, goal: Optional[str] = None, meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        now = time.time()
        with self._conn() as c:
            row = c.execute("SELECT * FROM sessions WHERE id = ?", (session,)).fetchone()
            if row is None:
                c.execute("INSERT INTO sessions (id, goal, created, updated, meta) VALUES (?, ?, ?, ?, ?)",
                          (session, goal, now, now, json.dumps(meta or {})))
                return {"id": session, "goal": goal, "created": now, "updated": now, "meta": meta or {}}
            merged = json.loads(row["meta"] or "{}")
            merged.update(meta or {})
            new_goal = goal or row["goal"]
            c.execute("UPDATE sessions SET updated = ?, goal = ?, meta = ? WHERE id = ?",
                      (now, new_goal, json.dumps(merged), session))
            return {"id": session, "goal": new_goal, "created": row["created"], "updated": now, "meta": merged}

    def sessions(self, limit: int = 50) -> List[Dict[str, Any]]:
        with self._conn() as c:
            rows = c.execute("""
                SELECT s.id, s.goal, s.created, s.updated,
                       (SELECT COUNT(*) FROM taints t WHERE t.session = s.id) AS taints,
                       (SELECT COUNT(*) FROM incidents i WHERE i.session = s.id) AS incidents,
                       (SELECT COUNT(*) FROM events e WHERE e.session = s.id AND e.type = 'gate') AS gated
                FROM sessions s ORDER BY s.updated DESC LIMIT ?""", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def reset_session(self, session: str) -> None:
        with self._conn() as c:
            c.execute("DELETE FROM taints WHERE session = ?", (session,))
            if self._has_table(c, "checkpoints"):
                c.execute("DELETE FROM checkpoints WHERE session_id = ?", (session,))

    @staticmethod
    def _has_table(c: sqlite3.Connection, name: str) -> bool:
        return c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)).fetchone() is not None

    # taint ----------------------------------------------------------------------
    def add_taint(self, session: str, record: TaintRecord, meta: Optional[Dict[str, Any]] = None) -> None:
        with self._conn() as c:
            c.execute("INSERT OR REPLACE INTO taints (id, session, source, level, markers, snippet, meta, created) VALUES (?,?,?,?,?,?,?,?)",
                      (record.id, session, record.source_tool, record.taint_level, json.dumps(record.risk_markers),
                       record.snippet, json.dumps(meta or {}), record.timestamp))

    def active_taints(self, session: str, ttl_seconds: float) -> List[TaintRecord]:
        cutoff = time.time() - ttl_seconds
        with self._conn() as c:
            rows = c.execute("SELECT * FROM taints WHERE session = ? AND created >= ? ORDER BY created",
                             (session, cutoff)).fetchall()
        return [TaintRecord(id=r["id"], source_tool=r["source"], source_type="untrusted_payload", snippet=r["snippet"],
                            risk_markers=json.loads(r["markers"]), taint_level=r["level"], source_chain=[r["source"]],
                            timestamp=r["created"]) for r in rows]

    # events & incidents ---------------------------------------------------------
    def log_event(self, session: str, type_: str, tool: Optional[str] = None, kind: Optional[str] = None,
                  action: Optional[str] = None, rule: Optional[str] = None, latency_ms: Optional[float] = None) -> None:
        with self._conn() as c:
            c.execute("INSERT INTO events (session, created, type, tool, kind, action, rule, latency_ms) VALUES (?,?,?,?,?,?,?,?)",
                      (session, time.time(), type_, tool, kind, action, rule, latency_ms))

    def add_incident(self, session: str, **fields: Any) -> str:
        incident_id = f"INC-{uuid.uuid4().hex[:8]}"
        with self._conn() as c:
            c.execute("""INSERT INTO incidents (id, session, created, tool, kind, action, rule, reason, params, findings,
                         requester, source_chain, quarantine_id, restored_checkpoint, latency_ms)
                         VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
                      (incident_id, session, time.time(), fields["tool"], fields.get("kind"), fields["action"],
                       fields.get("rule"), fields["reason"], json.dumps(fields.get("params", {}), default=str)[:20000],
                       json.dumps(fields.get("findings", []), default=str), json.dumps(fields.get("requester"), default=str),
                       json.dumps(fields.get("source_chain", []), default=str), fields.get("quarantine_id"),
                       fields.get("restored_checkpoint"), fields.get("latency_ms")))
        return incident_id

    def incidents(self, session: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        q = "SELECT * FROM incidents"
        args: List[Any] = []
        if session:
            q += " WHERE session = ?"
            args.append(session)
        q += " ORDER BY created DESC LIMIT ?"
        args.append(limit)
        with self._conn() as c:
            rows = c.execute(q, args).fetchall()
        out = []
        for r in rows:
            d = dict(r)
            for k in ("params", "findings", "requester", "source_chain"):
                d[k] = json.loads(d[k]) if d.get(k) else None
            out.append(d)
        return out

    def stats(self, session: Optional[str] = None) -> Dict[str, Any]:
        where, args = ("WHERE session = ?", [session]) if session else ("", [])
        with self._conn() as c:
            rows = c.execute(f"SELECT action, COUNT(*) n, AVG(latency_ms) avg_ms, MAX(latency_ms) max_ms FROM events {where} "
                             f"{'AND' if where else 'WHERE'} type = 'gate' GROUP BY action", args).fetchall()
            taint_n = c.execute(f"SELECT COUNT(*) FROM taints {where}", args).fetchone()[0]
        by_action = {r["action"]: {"count": r["n"], "avg_ms": r["avg_ms"], "max_ms": r["max_ms"]} for r in rows}
        return {"decisions": by_action, "taints": taint_n}
