"""
Storage Backends for WipprHarness CheckpointManager.
Supports both in-memory fast storage and persistent SQLite database storage.
"""

import sqlite3
from contextlib import contextmanager
import json
from abc import ABC, abstractmethod
from typing import Any, Dict, Iterator, List, Optional
from .models import CheckpointFrame


class StorageBackend(ABC):
    @abstractmethod
    def save(self, frame: CheckpointFrame) -> None:
        pass

    @abstractmethod
    def get(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        pass

    @abstractmethod
    def list_all(self) -> List[CheckpointFrame]:
        pass

    @abstractmethod
    def clear(self) -> None:
        pass


class MemoryBackend(StorageBackend):
    def __init__(self):
        self._store: Dict[str, CheckpointFrame] = {}
        self._ordered: List[str] = []

    def save(self, frame: CheckpointFrame) -> None:
        if frame.checkpoint_id not in self._store:
            self._ordered.append(frame.checkpoint_id)
        self._store[frame.checkpoint_id] = frame

    def get(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        return self._store.get(checkpoint_id)

    def list_all(self) -> List[CheckpointFrame]:
        return [self._store[cid] for cid in self._ordered]

    def clear(self) -> None:
        self._store.clear()
        self._ordered.clear()


class SQLiteBackend(StorageBackend):
    """Persistent checkpoint storage. Checkpoints are scoped to `session_id` so one database can hold many sessions."""

    def __init__(self, db_path: str = "wippr_checkpoints.db", session_id: str = "default"):
        self.db_path = db_path
        self.session_id = session_id
        self._init_db()

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        # sqlite3's own context manager commits but never closes; close explicitly so
        # long-running servers don't leak a file handle per call.
        conn = sqlite3.connect(self.db_path, timeout=10)
        try:
            conn.execute("PRAGMA journal_mode=WAL")
            with conn:
                yield conn
        finally:
            conn.close()

    def _init_db(self):
        with self._connect() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS checkpoints (
                    checkpoint_id TEXT PRIMARY KEY,
                    step_index INTEGER,
                    user_goal TEXT,
                    status TEXT,
                    created_at REAL,
                    raw_data TEXT
                )
            """)
            cols = {row[1] for row in conn.execute("PRAGMA table_info(checkpoints)")}
            if "session_id" not in cols:
                conn.execute("ALTER TABLE checkpoints ADD COLUMN session_id TEXT NOT NULL DEFAULT 'default'")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_checkpoints_session ON checkpoints(session_id, created_at)")

    def save(self, frame: CheckpointFrame) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints (checkpoint_id, session_id, step_index, user_goal, status, created_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (frame.checkpoint_id, self.session_id, frame.step_index, frame.user_goal,
                 frame.status, frame.created_at, frame.model_dump_json())
            )

    def get(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT raw_data FROM checkpoints WHERE checkpoint_id = ? AND session_id = ?",
                (checkpoint_id, self.session_id)
            ).fetchone()
        return CheckpointFrame(**json.loads(row[0])) if row else None

    def list_all(self) -> List[CheckpointFrame]:
        with self._connect() as conn:
            rows = conn.execute(
                "SELECT raw_data FROM checkpoints WHERE session_id = ? ORDER BY created_at ASC, step_index ASC",
                (self.session_id,)
            ).fetchall()
        return [CheckpointFrame(**json.loads(r[0])) for r in rows]

    def clear(self) -> None:
        with self._connect() as conn:
            conn.execute("DELETE FROM checkpoints WHERE session_id = ?", (self.session_id,))
