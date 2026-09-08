from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

ENTITY_TYPES = frozenset({"ip", "user", "host", "hash", "domain"})
# host is stored for inventory, but case-to-case expansion ignores it so every
# alert on pop-os-native does not show up as "related".
_FOLLOW_TYPES_FROM_CASE = frozenset({"ip", "user", "hash", "domain"})
LOG = logging.getLogger(__name__)


def normalize_entity(entity_type: str, value: str) -> tuple[str, str]:
    et = (entity_type or "").strip().lower()
    val = (value or "").strip()
    if et in {"hash", "domain"}:
        val = val.lower()
    return et, val


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

                CREATE TABLE IF NOT EXISTS entities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    updated_at TEXT NOT NULL,
                    UNIQUE(entity_type, value)
                );

                CREATE TABLE IF NOT EXISTS entity_links (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    entity_id INTEGER NOT NULL,
                    alert_id TEXT,
                    case_id INTEGER,
                    created_at TEXT NOT NULL,
                    FOREIGN KEY(entity_id) REFERENCES entities(id),
                    FOREIGN KEY(case_id) REFERENCES cases(id)
                );

                CREATE INDEX IF NOT EXISTS idx_entity_links_entity
                    ON entity_links(entity_id);
                CREATE INDEX IF NOT EXISTS idx_entity_links_case
                    ON entity_links(case_id);
                CREATE INDEX IF NOT EXISTS idx_entity_links_alert
                    ON entity_links(alert_id);
                """
            )
            self._ensure_unique_alert_id(conn)
            self._ensure_feedback_schema(conn)

    @staticmethod
    def _ensure_unique_alert_id(conn: sqlite3.Connection) -> None:
        """Partial unique index on alert_id (NULLs allowed). Dedup existing rows first."""
        conn.execute(
            "UPDATE cases SET alert_id = NULL WHERE alert_id IS NOT NULL AND trim(alert_id) = ''"
        )
        dup_ids = [
            int(r[0])
            for r in conn.execute(
                """
                SELECT c.id FROM cases c
                WHERE c.alert_id IS NOT NULL
                  AND c.id NOT IN (
                    SELECT MIN(id) FROM cases
                    WHERE alert_id IS NOT NULL
                    GROUP BY alert_id
                  )
                """
            ).fetchall()
        ]
        if dup_ids:
            placeholders = ",".join("?" * len(dup_ids))
            conn.execute(
                f"DELETE FROM case_notes WHERE case_id IN ({placeholders})",
                dup_ids,
            )
            conn.execute(
                f"DELETE FROM entity_links WHERE case_id IN ({placeholders})",
                dup_ids,
            )
            conn.execute(
                f"DELETE FROM cases WHERE id IN ({placeholders})",
                dup_ids,
            )
        conn.execute(
            """
            CREATE UNIQUE INDEX IF NOT EXISTS idx_cases_alert_id_unique
            ON cases(alert_id)
            WHERE alert_id IS NOT NULL
            """
        )

    @staticmethod
    def _ensure_feedback_schema(conn: sqlite3.Connection) -> None:
        cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(cases)")}
        if "rule_id" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN rule_id TEXT")
        if "source_ip" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN source_ip TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS triage_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                alert_id TEXT,
                rule_id TEXT,
                source_ip TEXT,
                disposition TEXT,
                approved INTEGER NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_triage_feedback_rule_ip
            ON triage_feedback(rule_id, source_ip, approved)
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
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        now = self._now()
        aid = (alert_id or "").strip() or None
        rid = (rule_id or "").strip() or None
        sip = (source_ip or "").strip() or None
        with self._connect() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO cases (
                        title, status, severity, alert_id, agent_name,
                        summary, recommended_action, created_at, updated_at,
                        rule_id, source_ip
                    ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        title,
                        severity,
                        aid,
                        agent_name,
                        summary,
                        recommended_action,
                        now,
                        now,
                        rid,
                        sip,
                    ),
                )
                case_id = cur.lastrowid
            except sqlite3.IntegrityError:
                conn.rollback()
                if not aid:
                    raise
                row = conn.execute(
                    "SELECT id FROM cases WHERE alert_id = ?",
                    (aid,),
                ).fetchone()
                if not row:
                    raise
                existing = self.get_case(int(row["id"]))
                existing["duplicate"] = True
                return existing
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
        updated = self.update_case(
            case_id,
            status=status,
            note=audit,
            author=author,
        )
        try:
            self.record_feedback(case_id, approved=approved, note=detail)
        except Exception:
            LOG.warning("failed to record triage feedback for case %s", case_id, exc_info=True)
        return updated

    def resolve_proposals(
        self,
        case_ids: list[int],
        *,
        approved: bool,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Bulk Approve / Reject. Record-only; never containment."""
        updated: list[dict[str, Any]] = []
        skipped: list[dict[str, Any]] = []
        errors: list[dict[str, Any]] = []
        seen: set[int] = set()
        for raw in case_ids:
            try:
                cid = int(raw)
            except (TypeError, ValueError):
                errors.append({"id": raw, "error": "invalid_id"})
                continue
            if cid in seen:
                continue
            seen.add(cid)
            case = self.get_case(cid)
            if case.get("error"):
                errors.append({"id": cid, "error": "case not found"})
                continue
            st = str(case.get("status") or "").lower()
            if st != "open":
                skipped.append({"id": cid, "status": st, "reason": "not_open"})
                continue
            result = self.resolve_proposal(
                cid,
                approved=approved,
                note=note,
                author=author,
            )
            if result.get("error"):
                errors.append({"id": cid, "error": result.get("error")})
            else:
                updated.append({"id": cid, "status": result.get("status")})
        return {
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "count": len(updated),
            "approved": approved,
            "containment_executed": False,
        }

    def auto_close_noise(
        self,
        case_id: int,
        *,
        note: str = "",
        author: str = "autonomy_loop",
    ) -> dict[str, Any]:
        """Close a heuristic-noise case without paging Discord / Cursor.

        Records feedback as a reject so the same rule_id+source_ip is skipped.
        Never executes containment.
        """
        case = self.get_case(case_id)
        if case.get("error"):
            return case
        proposed = case.get("recommended_action") or "(none)"
        detail = note.strip() or "heuristic noise auto-closed (no HITL page)"
        audit = (
            f"[auto_closed_noise] CLOSED\n"
            f"proposed_action={proposed}\n"
            f"note={detail}\n"
            f"containment=not_executed\n"
            f"hitl=not_paged"
        )
        updated = self.update_case(
            case_id,
            status="auto_closed",
            note=audit,
            author=author,
        )
        try:
            self.record_feedback(case_id, approved=False, note=detail)
        except Exception:
            LOG.warning("failed to record triage feedback for auto-closed case %s", case_id, exc_info=True)
        return updated

    def record_feedback(
        self,
        case_id: int,
        *,
        approved: bool,
        note: str = "",
    ) -> dict[str, Any]:
        """Store a human decision for later skip/eval (no containment)."""
        case = self.get_case(case_id)
        if case.get("error"):
            return case
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO triage_feedback (
                    case_id, alert_id, rule_id, source_ip, disposition,
                    approved, note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    case.get("alert_id"),
                    case.get("rule_id"),
                    case.get("source_ip"),
                    case.get("disposition"),
                    1 if approved else 0,
                    note,
                    now,
                ),
            )
        return {"ok": True, "case_id": case_id, "approved": approved}

    def rejected_similar(
        self,
        *,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        days: int = 14,
    ) -> dict[str, Any]:
        """True when the same rule_id + source_ip was rejected recently."""
        rid = (rule_id or "").strip()
        sip = (source_ip or "").strip()
        if not rid or not sip:
            return {"skip": False, "count": 0, "reason": "need_rule_and_source"}
        cutoff = datetime.now(timezone.utc).timestamp() - max(1, days) * 86400
        count = 0
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT created_at FROM triage_feedback
                WHERE approved = 0
                  AND rule_id = ?
                  AND source_ip = ?
                """,
                (rid, sip),
            ).fetchall()
        for row in rows:
            ts = str(row["created_at"] or "")
            try:
                parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                if parsed.tzinfo is None:
                    parsed = parsed.replace(tzinfo=timezone.utc)
                if parsed.timestamp() >= cutoff:
                    count += 1
            except ValueError:
                count += 1
        return {
            "skip": count >= 1,
            "count": count,
            "reason": "rejected_same_rule_and_source" if count >= 1 else "no_match",
            "rule_id": rid,
            "source_ip": sip,
        }

    def feedback_summary(self, limit: int = 50) -> dict[str, Any]:
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT id, case_id, alert_id, rule_id, source_ip, disposition,
                       approved, note, created_at
                FROM triage_feedback
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
            totals = conn.execute(
                """
                SELECT
                    COUNT(*) AS n,
                    SUM(CASE WHEN approved = 1 THEN 1 ELSE 0 END) AS approved_n,
                    SUM(CASE WHEN approved = 0 THEN 1 ELSE 0 END) AS rejected_n
                FROM triage_feedback
                """
            ).fetchone()
        items = [dict(r) for r in rows]
        for item in items:
            item["approved"] = bool(item.get("approved"))
        n = int(totals["n"] or 0) if totals else 0
        approved_n = int(totals["approved_n"] or 0) if totals else 0
        rejected_n = int(totals["rejected_n"] or 0) if totals else 0
        return {
            "count": n,
            "approved": approved_n,
            "rejected": rejected_n,
            "items": items,
        }

    def upsert_entity(self, entity_type: str, value: str) -> dict[str, Any]:
        """Insert or refresh an entity (ip / user / host / hash / domain)."""
        et, val = normalize_entity(entity_type, value)
        if et not in ENTITY_TYPES:
            return {"error": "invalid entity_type", "entity_type": entity_type}
        if not val:
            return {"error": "empty entity value"}
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO entities (entity_type, value, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(entity_type, value) DO UPDATE SET updated_at = excluded.updated_at
                """,
                (et, val, now, now),
            )
            row = conn.execute(
                "SELECT * FROM entities WHERE entity_type = ? AND value = ?",
                (et, val),
            ).fetchone()
        return dict(row)

    def link_alert_to_entity(
        self,
        entity_id: int,
        alert_id: str,
        *,
        case_id: Optional[int] = None,
    ) -> dict[str, Any]:
        """Link an entity to a Wazuh alert_id (and optionally a case)."""
        return self._link_entity(entity_id, alert_id=alert_id, case_id=case_id)

    def link_case_to_entity(
        self,
        entity_id: int,
        case_id: int,
        *,
        alert_id: Optional[str] = None,
    ) -> dict[str, Any]:
        """Link an entity to a local case (and optionally an alert_id)."""
        return self._link_entity(entity_id, alert_id=alert_id, case_id=case_id)

    def _link_entity(
        self,
        entity_id: int,
        *,
        alert_id: Optional[str] = None,
        case_id: Optional[int] = None,
    ) -> dict[str, Any]:
        aid = (alert_id or "").strip() or None
        if not aid and case_id is None:
            return {"error": "alert_id or case_id required"}
        with self._connect() as conn:
            ent = conn.execute("SELECT id FROM entities WHERE id = ?", (entity_id,)).fetchone()
            if not ent:
                return {"error": "entity not found", "entity_id": entity_id}
            if case_id is not None:
                case = conn.execute("SELECT id FROM cases WHERE id = ?", (case_id,)).fetchone()
                if not case:
                    return {"error": "case not found", "id": case_id}
            existing = conn.execute(
                """
                SELECT * FROM entity_links
                WHERE entity_id = ?
                  AND ifnull(alert_id, '') = ifnull(?, '')
                  AND ifnull(case_id, 0) = ifnull(?, 0)
                """,
                (entity_id, aid, case_id),
            ).fetchone()
            if existing:
                return dict(existing)
            cur = conn.execute(
                """
                INSERT INTO entity_links (entity_id, alert_id, case_id, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (entity_id, aid, case_id, self._now()),
            )
            row = conn.execute(
                "SELECT * FROM entity_links WHERE id = ?",
                (cur.lastrowid,),
            ).fetchone()
        return dict(row)

    def find_related(
        self,
        *,
        case_id: Optional[int] = None,
        alert_id: Optional[str] = None,
        entity_type: Optional[str] = None,
        value: Optional[str] = None,
        entity_id: Optional[int] = None,
        include_hosts: bool = False,
    ) -> dict[str, Any]:
        """
        Find other cases (and alert ids) that share entities with the seed.

        Seed with case_id, alert_id, entity_id, or entity_type+value.
        From a case/alert, host entities are skipped unless include_hosts=True
        so agent name does not relate every case on the same host.
        """
        aid = (alert_id or "").strip() or None
        et, val = normalize_entity(entity_type or "", value or "")
        if entity_id is None and case_id is None and not aid and not (et and val):
            return {"error": "provide case_id, alert_id, entity_id, or entity_type+value"}

        follow_types = ENTITY_TYPES if include_hosts else _FOLLOW_TYPES_FROM_CASE
        explicit_entity = entity_id is not None or bool(et and val)

        with self._connect() as conn:
            seed_ids: set[int] = set()
            if entity_id is not None:
                row = conn.execute("SELECT id FROM entities WHERE id = ?", (entity_id,)).fetchone()
                if row:
                    seed_ids.add(int(row["id"]))
            if et and val:
                row = conn.execute(
                    "SELECT id FROM entities WHERE entity_type = ? AND value = ?",
                    (et, val),
                ).fetchone()
                if row:
                    seed_ids.add(int(row["id"]))
            if case_id is not None:
                for row in conn.execute(
                    "SELECT entity_id FROM entity_links WHERE case_id = ?",
                    (case_id,),
                ):
                    seed_ids.add(int(row["entity_id"]))
            if aid:
                for row in conn.execute(
                    "SELECT entity_id FROM entity_links WHERE alert_id = ?",
                    (aid,),
                ):
                    seed_ids.add(int(row["entity_id"]))

            if not seed_ids:
                return {
                    "entities": [],
                    "related_cases": [],
                    "related_alert_ids": [],
                    "count": 0,
                }

            placeholders = ",".join("?" * len(seed_ids))
            entity_rows = conn.execute(
                f"SELECT * FROM entities WHERE id IN ({placeholders})",
                tuple(seed_ids),
            ).fetchall()
            entities = [dict(r) for r in entity_rows]
            entity_by_id = {int(e["id"]): e for e in entities}

            if not explicit_entity:
                walk_ids = [
                    eid
                    for eid, e in entity_by_id.items()
                    if e.get("entity_type") in follow_types
                ]
            else:
                walk_ids = list(seed_ids)

            if not walk_ids:
                return {
                    "entities": entities,
                    "related_cases": [],
                    "related_alert_ids": [],
                    "count": 0,
                }

            walk_ph = ",".join("?" * len(walk_ids))
            links = conn.execute(
                f"SELECT * FROM entity_links WHERE entity_id IN ({walk_ph})",
                tuple(walk_ids),
            ).fetchall()

            related_case_ids: set[int] = set()
            related_alert_ids: set[str] = set()
            case_entity_ids: dict[int, set[int]] = {}
            for link in links:
                lid = int(link["entity_id"])
                if link["case_id"] is not None:
                    cid = int(link["case_id"])
                    if case_id is None or cid != int(case_id):
                        related_case_ids.add(cid)
                        case_entity_ids.setdefault(cid, set()).add(lid)
                if link["alert_id"]:
                    laid = str(link["alert_id"])
                    if aid is None or laid != aid:
                        related_alert_ids.add(laid)

            related_cases: list[dict[str, Any]] = []
            if related_case_ids:
                cph = ",".join("?" * len(related_case_ids))
                crows = conn.execute(
                    f"SELECT * FROM cases WHERE id IN ({cph}) ORDER BY id DESC",
                    tuple(related_case_ids),
                ).fetchall()
                for crow in crows:
                    item = dict(crow)
                    matched = [
                        {
                            "id": entity_by_id[eid]["id"],
                            "entity_type": entity_by_id[eid]["entity_type"],
                            "value": entity_by_id[eid]["value"],
                        }
                        for eid in sorted(case_entity_ids.get(int(crow["id"]), set()))
                        if eid in entity_by_id
                    ]
                    item["matched_entities"] = matched
                    related_cases.append(item)

        return {
            "entities": entities,
            "related_cases": related_cases,
            "related_alert_ids": sorted(related_alert_ids),
            "count": len(related_cases),
        }
