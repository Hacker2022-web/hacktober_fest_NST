"""
Storage Backends for ShadowHarness CheckpointManager.
Supports both in-memory fast storage and persistent SQLite database storage.
"""

import sqlite3
import json
import time
from abc import ABC, abstractmethod
from typing import List, Optional, Dict, Any
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
        self._ordered: List[CheckpointFrame] = []

    def save(self, frame: CheckpointFrame) -> None:
        self._store[frame.checkpoint_id] = frame
        self._ordered.append(frame)

    def get(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        return self._store.get(checkpoint_id)

    def list_all(self) -> List[CheckpointFrame]:
        return list(self._ordered)

    def clear(self) -> None:
        self._store.clear()
        self._ordered.clear()


class SQLiteBackend(StorageBackend):
    def __init__(self, db_path: str = "shadowharness_checkpoints.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
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
            conn.commit()

    def save(self, frame: CheckpointFrame) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """
                INSERT OR REPLACE INTO checkpoints (checkpoint_id, step_index, user_goal, status, created_at, raw_data)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    frame.checkpoint_id,
                    frame.step_index,
                    frame.user_goal,
                    frame.status,
                    frame.created_at,
                    frame.model_dump_json()
                )
            )
            conn.commit()

    def get(self, checkpoint_id: str) -> Optional[CheckpointFrame]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_data FROM checkpoints WHERE checkpoint_id = ?", (checkpoint_id,))
            row = cursor.fetchone()
            if row:
                data = json.loads(row[0])
                return CheckpointFrame(**data)
        return None

    def list_all(self) -> List[CheckpointFrame]:
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT raw_data FROM checkpoints ORDER BY step_index ASC")
            rows = cursor.fetchall()
            return [CheckpointFrame(**json.loads(r[0])) for r in rows]

    def clear(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute("DELETE FROM checkpoints")
            conn.commit()
