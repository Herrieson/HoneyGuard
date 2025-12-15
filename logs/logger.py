from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any, Dict


class SqliteLogger:
    """Persist traces and events to sqlite."""

    def __init__(self, db_path: str = "logs/hse.db") -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        self._ensure_schema()

    def _ensure_schema(self) -> None:
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS traces (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    trace_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        return sqlite3.connect(self.db_path)

    def log_trace(self, session_id: str, trace_id: str, payload: Dict[str, Any]) -> None:
        with self._lock, self._connect() as conn:
            conn.execute(
                "INSERT INTO traces (session_id, trace_id, payload) VALUES (?, ?, ?)",
                (session_id, trace_id, json.dumps(payload, ensure_ascii=False)),
            )
            conn.commit()
