from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional


class CaseStore:
    """Simple SQLite case memory for agent triage (lab-local, not a SOAR)."""

    def __init__(self, db_path: str | Path) -> None:
        self.path = Path(db_path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self) -> None:
        with self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS cases (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    title TEXT NOT NULL,
                    status TEXT NOT NULL DEFAULT 'open',
                    severity TEXT NOT NULL DEFAULT 'medium',
                    alert_id TEXT,
                    agent_name TEXT,
                    summary TEXT,
                    disposition TEXT,
                    recommended_action TEXT,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL
                );

                CREATE TABLE IF NOT EXISTS case_notes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    case_id INTEGER NOT NULL,
                    author TEXT NOT NULL DEFAULT 'agent',
                    note TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );
                """
            )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    def open_case(
        self,
        *,
        title: str,
        alert_id: Optional[str] = None,
        agent_name: Optional[str] = None,
        summary: str = "",
        severity: str = "medium",
        recommended_action: str = "",
    ) -> dict[str, Any]:
        now = self._now()
        with self._connect() as conn:
            cur = conn.execute(
                """
                INSERT INTO cases (
                    title, status, severity, alert_id, agent_name,
                    summary, recommended_action, created_at, updated_at
                ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?)
                """,
                (title, severity, alert_id, agent_name, summary, recommended_action, now, now),
            )
            case_id = cur.lastrowid
        return self.get_case(case_id)

    def update_case(
        self,
        case_id: int,
        *,
        status: Optional[str] = None,
        disposition: Optional[str] = None,
        summary: Optional[str] = None,
        recommended_action: Optional[str] = None,
        note: Optional[str] = None,
        author: str = "agent",
    ) -> dict[str, Any]:
        fields: list[str] = []
        values: list[Any] = []
        if status is not None:
            fields.append("status = ?")
            values.append(status)
        if disposition is not None:
            fields.append("disposition = ?")
            values.append(disposition)
        if summary is not None:
            fields.append("summary = ?")
            values.append(summary)
        if recommended_action is not None:
            fields.append("recommended_action = ?")
            values.append(recommended_action)
        fields.append("updated_at = ?")
        values.append(self._now())
        values.append(case_id)

        with self._connect() as conn:
            if len(fields) > 1:
                conn.execute(f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", values)
            if note:
                conn.execute(
                    "INSERT INTO case_notes (case_id, author, note, created_at) VALUES (?, ?, ?, ?)",
                    (case_id, author, note, self._now()),
                )
        return self.get_case(case_id)

    def get_case(self, case_id: int) -> dict[str, Any]:
        with self._connect() as conn:
            row = conn.execute("SELECT * FROM cases WHERE id = ?", (case_id,)).fetchone()
            if not row:
                return {"error": "case not found", "id": case_id}
            notes = conn.execute(
                "SELECT id, author, note, created_at FROM case_notes WHERE case_id = ? ORDER BY id",
                (case_id,),
            ).fetchall()
        case = dict(row)
        case["notes"] = [dict(n) for n in notes]
        return case

    def list_cases(self, status: Optional[str] = None, limit: int = 50) -> dict[str, Any]:
        with self._connect() as conn:
            if status:
                rows = conn.execute(
                    "SELECT * FROM cases WHERE status = ? ORDER BY id DESC LIMIT ?",
                    (status, limit),
                ).fetchall()
            else:
                rows = conn.execute(
                    "SELECT * FROM cases ORDER BY id DESC LIMIT ?",
                    (limit,),
                ).fetchall()
        return {"cases": [dict(r) for r in rows], "count": len(rows)}

    def propose_action(
        self,
        case_id: int,
        action: str,
        *,
        rationale: str = "",
        auto_execute: bool = False,
    ) -> dict[str, Any]:
        """Record a proposed response. Lab-safe: never auto-executes containment."""
        payload = {
            "action": action,
            "rationale": rationale,
            "auto_execute": False,
            "executed": False,
            "note": "Lab mode: actions are proposals only until human approval is wired in.",
        }
        if auto_execute:
            payload["note"] = (
                "auto_execute requested but ignored — containment is disabled in this lab scaffold."
            )
        note = json.dumps(payload, indent=2)
        return self.update_case(
            case_id,
            recommended_action=action,
            note=f"[propose_action]\n{note}",
            author="agent",
        )

    def resolve_proposal(
        self,
        case_id: int,
        *,
        approved: bool,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """
        Record human approval/rejection of a proposed action.

        Lab-safe: never executes containment. Updates status + notes only.
        """
        case = self.get_case(case_id)
        if case.get("error"):
            return case

        decision = "APPROVED" if approved else "REJECTED"
        status = "approved" if approved else "rejected"
        proposed = case.get("recommended_action") or "(none)"
        detail = note.strip() or ("human approved proposal" if approved else "human rejected proposal")
        audit = (
            f"[human_approval] {decision}\n"
            f"proposed_action={proposed}\n"
            f"note={detail}\n"
            f"containment=not_executed"
        )
        return self.update_case(
            case_id,
            status=status,
            note=audit,
            author=author,
        )
