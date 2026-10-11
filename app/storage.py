from __future__ import annotations
import json
import sqlite3
from pathlib import Path
from schemas.models import AssessmentRun, AgentMessage


class Storage:
    def __init__(self, path: str):
        if path != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.executescript("""
            CREATE TABLE IF NOT EXISTS runs (id TEXT PRIMARY KEY, created_at TEXT, data TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS events (seq INTEGER PRIMARY KEY AUTOINCREMENT, id TEXT UNIQUE, run_id TEXT, data TEXT NOT NULL);
            CREATE INDEX IF NOT EXISTS events_run ON events(run_id, seq);
        """)
        self.db.commit()

    def save(self, run: AssessmentRun):
        self.db.execute("INSERT OR REPLACE INTO runs VALUES (?, ?, ?)", (run.run_id, run.created_at, run.model_dump_json()))
        self.db.commit()

    def event(self, message: AgentMessage):
        self.db.execute("INSERT OR IGNORE INTO events(id, run_id, data) VALUES (?, ?, ?)", (message.event_id, message.run_id, message.model_dump_json()))
        self.db.commit()

    def get(self, run_id: str) -> AssessmentRun | None:
        row = self.db.execute("SELECT data FROM runs WHERE id=?", (run_id,)).fetchone()
        return AssessmentRun.model_validate_json(row[0]) if row else None

    def list(self) -> list[dict]:
        return [json.loads(row[0]) for row in self.db.execute("SELECT data FROM runs ORDER BY created_at DESC LIMIT 50")]

    def events(self, run_id: str, after: int = 0) -> list[dict]:
        return [{**json.loads(data), "seq": seq} for seq, data in self.db.execute("SELECT seq,data FROM events WHERE run_id=? AND seq>? ORDER BY seq", (run_id, after))]

