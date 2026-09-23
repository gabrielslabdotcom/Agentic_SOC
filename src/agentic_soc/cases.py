from __future__ import annotations

import json
import logging
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from agentic_soc.analyst_outcomes import (
    INFORMATIONAL,
    coerce_analyst_disposition,
    feedback_approved_int,
    skips_repeats,
)
from agentic_soc.triage import fallback_brief_from_case

ENTITY_TYPES = frozenset({"ip", "user", "host", "hash", "domain"})
# host is stored for inventory, but case-to-case expansion ignores it so every
# alert on pop-os-native does not show up as "related".
_FOLLOW_TYPES_FROM_CASE = frozenset({"ip", "user", "hash", "domain"})
# Analyst-managed suppressions force auto-close as these dispositions only.
SUPPRESSION_DISPOSITIONS = frozenset({"informational", "false_positive"})
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
                    analyst_disposition TEXT,
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
            self._ensure_suppressions_schema(conn)

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
        if "analyst_disposition" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN analyst_disposition TEXT")
        if "brief_json" not in cols:
            conn.execute("ALTER TABLE cases ADD COLUMN brief_json TEXT")
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS triage_feedback (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER,
                alert_id TEXT,
                rule_id TEXT,
                source_ip TEXT,
                disposition TEXT,
                analyst_disposition TEXT,
                approved INTEGER NOT NULL,
                note TEXT,
                created_at TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            )
            """
        )
        fb_cols = {str(r[1]) for r in conn.execute("PRAGMA table_info(triage_feedback)")}
        if "analyst_disposition" not in fb_cols:
            conn.execute("ALTER TABLE triage_feedback ADD COLUMN analyst_disposition TEXT")
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_triage_feedback_rule_ip
            ON triage_feedback(rule_id, source_ip, approved)
            """
        )

    @staticmethod
    def _ensure_suppressions_schema(conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS rule_suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                rule_id TEXT NOT NULL,
                source_ip TEXT,
                disposition TEXT NOT NULL,
                note TEXT,
                created_by TEXT NOT NULL DEFAULT 'human',
                created_at TEXT NOT NULL,
                expires_at TEXT,
                disabled_at TEXT
            )
            """
        )
        conn.execute(
            """
            CREATE INDEX IF NOT EXISTS idx_rule_suppressions_rule
            ON rule_suppressions(rule_id, disabled_at)
            """
        )

    @staticmethod
    def _now() -> str:
        return datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _parse_ts(value: str) -> Optional[float]:
        ts = (value or "").strip()
        if not ts:
            return None
        try:
            parsed = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            return parsed.timestamp()
        except ValueError:
            return None

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
        brief: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        now = self._now()
        aid = (alert_id or "").strip() or None
        rid = (rule_id or "").strip() or None
        sip = (source_ip or "").strip() or None
        brief_json = json.dumps(brief, default=str) if brief else None
        with self._connect() as conn:
            try:
                cur = conn.execute(
                    """
                    INSERT INTO cases (
                        title, status, severity, alert_id, agent_name,
                        summary, recommended_action, created_at, updated_at,
                        rule_id, source_ip, brief_json
                    ) VALUES (?, 'open', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                        brief_json,
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
        analyst_disposition: Optional[str] = None,
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
        if analyst_disposition is not None:
            fields.append("analyst_disposition = ?")
            values.append(analyst_disposition)
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
        case["brief"] = self._brief_for(case)
        return case

    @staticmethod
    def _brief_for(case: dict[str, Any]) -> dict[str, Any]:
        raw = case.get("brief_json")
        if isinstance(raw, str) and raw.strip():
            try:
                parsed = json.loads(raw)
            except json.JSONDecodeError:
                parsed = None
            if isinstance(parsed, dict) and parsed.get("headline"):
                return parsed
        return fallback_brief_from_case(case)

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
        cases = [dict(r) for r in rows]
        for item in cases:
            item["brief"] = self._brief_for(item)
        return {"cases": cases, "count": len(cases)}

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
        disposition: Optional[str] = None,
        approved: Optional[bool] = None,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """
        Record a human closing outcome for a proposed action.

        Lab-safe: never executes containment. Updates status + notes only.
        ``approved`` is a deprecated alias (true→confirmed_compromise,
        false→false_positive).
        """
        case = self.get_case(case_id)
        if case.get("error"):
            return case
        try:
            outcome = coerce_analyst_disposition(
                disposition=disposition, approved=approved
            )
        except ValueError as exc:
            return {"error": str(exc), "id": case_id}

        skip = skips_repeats(outcome)
        proposed = case.get("recommended_action") or "(none)"
        detail = note.strip() or f"human closed as {outcome}"
        audit = (
            f"[human_approval] {outcome.upper()}\n"
            f"analyst_disposition={outcome}\n"
            f"proposed_action={proposed}\n"
            f"note={detail}\n"
            f"skip_repeats={'true' if skip else 'false'}\n"
            f"containment=not_executed"
        )
        updated = self.update_case(
            case_id,
            status=outcome,
            analyst_disposition=outcome,
            note=audit,
            author=author,
        )
        try:
            self.record_feedback(
                case_id,
                analyst_disposition=outcome,
                note=detail,
            )
        except Exception:
            LOG.warning("failed to record triage feedback for case %s", case_id, exc_info=True)
        return updated

    def resolve_proposals(
        self,
        case_ids: list[int],
        *,
        disposition: Optional[str] = None,
        approved: Optional[bool] = None,
        note: str = "",
        author: str = "human",
    ) -> dict[str, Any]:
        """Bulk close with an analyst outcome. Record-only; never containment."""
        try:
            outcome = coerce_analyst_disposition(
                disposition=disposition, approved=approved
            )
        except ValueError as exc:
            return {
                "updated": [],
                "skipped": [],
                "errors": [{"error": str(exc)}],
                "count": 0,
                "analyst_disposition": None,
                "containment_executed": False,
            }
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
                disposition=outcome,
                note=note,
                author=author,
            )
            if result.get("error"):
                errors.append({"id": cid, "error": result.get("error")})
            else:
                updated.append(
                    {
                        "id": cid,
                        "status": result.get("status"),
                        "analyst_disposition": result.get("analyst_disposition"),
                    }
                )
        return {
            "updated": updated,
            "skipped": skipped,
            "errors": errors,
            "count": len(updated),
            "analyst_disposition": outcome,
            "skip_repeats": skips_repeats(outcome),
            "containment_executed": False,
        }

    def auto_close_noise(
        self,
        case_id: int,
        *,
        note: str = "",
        author: str = "autonomy_loop",
        disposition: Optional[str] = None,
        close_status: str = "auto_closed",
    ) -> dict[str, Any]:
        """Close a heuristic-noise or suppressed case without paging Discord / Cursor.

        Records feedback so related skip keys can fire. Never executes containment.
        """
        case = self.get_case(case_id)
        if case.get("error"):
            return case
        outcome = (disposition or INFORMATIONAL).strip().lower()
        if outcome not in SUPPRESSION_DISPOSITIONS:
            outcome = INFORMATIONAL
        proposed = case.get("recommended_action") or "(none)"
        detail = note.strip() or "heuristic noise auto-closed (no HITL page)"
        audit = (
            f"[auto_closed_noise] CLOSED\n"
            f"analyst_disposition={outcome}\n"
            f"proposed_action={proposed}\n"
            f"note={detail}\n"
            f"containment=not_executed\n"
            f"hitl=not_paged"
        )
        updated = self.update_case(
            case_id,
            status=close_status,
            disposition=outcome,
            analyst_disposition=outcome,
            note=audit,
            author=author,
        )
        try:
            self.record_feedback(
                case_id,
                analyst_disposition=outcome,
                note=detail,
            )
        except Exception:
            LOG.warning("failed to record triage feedback for auto-closed case %s", case_id, exc_info=True)
        return updated

    def record_feedback(
        self,
        case_id: int,
        *,
        analyst_disposition: Optional[str] = None,
        approved: Optional[bool] = None,
        note: str = "",
    ) -> dict[str, Any]:
        """Store a human (or auto-close) decision for later skip/eval."""
        case = self.get_case(case_id)
        if case.get("error"):
            return case
        outcome = coerce_analyst_disposition(
            disposition=analyst_disposition, approved=approved
        )
        approved_n = feedback_approved_int(outcome)
        now = self._now()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO triage_feedback (
                    case_id, alert_id, rule_id, source_ip, disposition,
                    analyst_disposition, approved, note, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    case_id,
                    case.get("alert_id"),
                    case.get("rule_id"),
                    case.get("source_ip"),
                    case.get("disposition"),
                    outcome,
                    approved_n,
                    note,
                    now,
                ),
            )
        return {
            "ok": True,
            "case_id": case_id,
            "approved": bool(approved_n),
            "analyst_disposition": outcome,
        }

    def rejected_similar(
        self,
        *,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
        days: int = 14,
    ) -> dict[str, Any]:
        """True when the same rule_id + source_ip was skip-closed recently."""
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
                WHERE rule_id = ?
                  AND source_ip = ?
                  AND (
                    analyst_disposition IN (
                      'false_positive', 'benign', 'informational', 'duplicate'
                    )
                    OR (
                      (analyst_disposition IS NULL OR analyst_disposition = '')
                      AND approved = 0
                    )
                  )
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
                       analyst_disposition, approved, note, created_at
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

    def queue_metrics(self) -> dict[str, Any]:
        """Counts for the analyst UI strip (open / auto-closed / human outcomes)."""
        human_statuses = frozenset(
            {
                "false_positive",
                "benign",
                "informational",
                "duplicate",
                "confirmed_compromise",
                "approved",
                "rejected",
            }
        )
        with self._connect() as conn:
            status_rows = conn.execute(
                "SELECT status, COUNT(*) AS n FROM cases GROUP BY status"
            ).fetchall()
            by_status = {str(r["status"] or ""): int(r["n"] or 0) for r in status_rows}
            cases_total = int(
                conn.execute("SELECT COUNT(*) AS n FROM cases").fetchone()["n"] or 0
            )
            feedback_total = int(
                conn.execute("SELECT COUNT(*) AS n FROM triage_feedback").fetchone()["n"]
                or 0
            )
            ad_rows = conn.execute(
                """
                SELECT analyst_disposition, COUNT(*) AS n
                FROM cases
                WHERE analyst_disposition IS NOT NULL
                  AND trim(analyst_disposition) != ''
                  AND status != 'auto_closed'
                GROUP BY analyst_disposition
                """
            ).fetchall()
            human_outcomes = {
                str(r["analyst_disposition"]): int(r["n"] or 0) for r in ad_rows
            }
            active_suppressions = int(
                conn.execute(
                    """
                    SELECT COUNT(*) AS n FROM rule_suppressions
                    WHERE disabled_at IS NULL OR trim(disabled_at) = ''
                    """
                ).fetchone()["n"]
                or 0
            )
        human_closed = sum(int(by_status.get(s) or 0) for s in human_statuses)
        return {
            "cases_total": cases_total,
            "open": int(by_status.get("open") or 0),
            "auto_closed": int(by_status.get("auto_closed") or 0),
            "human_closed": human_closed,
            "human_outcomes": human_outcomes,
            "by_status": by_status,
            "feedback_total": feedback_total,
            "active_suppressions": active_suppressions,
            "legacy_approved": int(by_status.get("approved") or 0),
            "legacy_rejected": int(by_status.get("rejected") or 0),
        }

    def list_suppressions(
        self,
        *,
        include_disabled: bool = False,
        limit: int = 100,
    ) -> dict[str, Any]:
        limit = max(1, min(int(limit), 500))
        with self._connect() as conn:
            if include_disabled:
                rows = conn.execute(
                    """
                    SELECT * FROM rule_suppressions
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
            else:
                rows = conn.execute(
                    """
                    SELECT * FROM rule_suppressions
                    WHERE disabled_at IS NULL OR trim(disabled_at) = ''
                    ORDER BY id DESC
                    LIMIT ?
                    """,
                    (limit,),
                ).fetchall()
        items = [dict(r) for r in rows]
        now_ts = datetime.now(timezone.utc).timestamp()
        for item in items:
            item["active"] = self._suppression_row_active(item, now_ts=now_ts)
            item["any_source"] = not bool((item.get("source_ip") or "").strip())
        return {"suppressions": items, "count": len(items)}

    def add_suppression(
        self,
        *,
        rule_id: str,
        disposition: str = "informational",
        source_ip: Optional[str] = None,
        note: str = "",
        created_by: str = "human",
        expires_at: Optional[str] = None,
    ) -> dict[str, Any]:
        rid = (rule_id or "").strip()
        if not rid:
            return {"error": "rule_id required"}
        disp = (disposition or "").strip().lower()
        if disp not in SUPPRESSION_DISPOSITIONS:
            return {
                "error": (
                    f"disposition must be one of {sorted(SUPPRESSION_DISPOSITIONS)}; "
                    "confirmed_compromise cannot create a suppression"
                ),
                "disposition": disposition,
            }
        sip = (source_ip or "").strip() or None
        exp = (expires_at or "").strip() or None
        if exp is not None and self._parse_ts(exp) is None:
            return {"error": "expires_at must be ISO-8601", "expires_at": expires_at}
        now = self._now()
        with self._connect() as conn:
            # Re-enable an identical active row instead of duplicating
            existing = conn.execute(
                """
                SELECT * FROM rule_suppressions
                WHERE rule_id = ?
                  AND ifnull(source_ip, '') = ifnull(?, '')
                  AND disposition = ?
                  AND (disabled_at IS NULL OR trim(disabled_at) = '')
                ORDER BY id DESC
                LIMIT 1
                """,
                (rid, sip, disp),
            ).fetchone()
            if existing:
                conn.execute(
                    """
                    UPDATE rule_suppressions
                    SET note = ?, created_by = ?, expires_at = ?, disabled_at = NULL
                    WHERE id = ?
                    """,
                    (note or existing["note"], created_by, exp, int(existing["id"])),
                )
                row = conn.execute(
                    "SELECT * FROM rule_suppressions WHERE id = ?",
                    (int(existing["id"]),),
                ).fetchone()
                item = dict(row)
                item["reused"] = True
            else:
                cur = conn.execute(
                    """
                    INSERT INTO rule_suppressions (
                        rule_id, source_ip, disposition, note,
                        created_by, created_at, expires_at, disabled_at
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, NULL)
                    """,
                    (rid, sip, disp, note, created_by, now, exp),
                )
                row = conn.execute(
                    "SELECT * FROM rule_suppressions WHERE id = ?",
                    (cur.lastrowid,),
                ).fetchone()
                item = dict(row)
                item["reused"] = False
        item["active"] = True
        item["any_source"] = not bool((item.get("source_ip") or "").strip())
        return item

    def disable_suppression(self, suppression_id: int) -> dict[str, Any]:
        now = self._now()
        with self._connect() as conn:
            row = conn.execute(
                "SELECT * FROM rule_suppressions WHERE id = ?",
                (suppression_id,),
            ).fetchone()
            if not row:
                return {"error": "suppression not found", "id": suppression_id}
            conn.execute(
                "UPDATE rule_suppressions SET disabled_at = ? WHERE id = ?",
                (now, suppression_id),
            )
            updated = conn.execute(
                "SELECT * FROM rule_suppressions WHERE id = ?",
                (suppression_id,),
            ).fetchone()
        item = dict(updated)
        item["active"] = False
        item["any_source"] = not bool((item.get("source_ip") or "").strip())
        return item

    def match_suppression(
        self,
        *,
        rule_id: Optional[str] = None,
        source_ip: Optional[str] = None,
    ) -> dict[str, Any]:
        """Return the best active suppression for this rule (+ optional source).

        Empty suppression source_ip means "any source" (including alerts with
        no extracted IP). Prefer an exact source match over any-source.
        """
        rid = (rule_id or "").strip()
        sip = (source_ip or "").strip()
        if not rid:
            return {"match": False, "reason": "need_rule_id"}
        now_ts = datetime.now(timezone.utc).timestamp()
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT * FROM rule_suppressions
                WHERE rule_id = ?
                  AND (disabled_at IS NULL OR trim(disabled_at) = '')
                ORDER BY id DESC
                """,
                (rid,),
            ).fetchall()
        exact: Optional[dict[str, Any]] = None
        any_source: Optional[dict[str, Any]] = None
        for row in rows:
            item = dict(row)
            if not self._suppression_row_active(item, now_ts=now_ts):
                continue
            row_sip = (item.get("source_ip") or "").strip()
            if row_sip:
                if sip and row_sip == sip:
                    exact = item
                    break
            else:
                if any_source is None:
                    any_source = item
        chosen = exact or any_source
        if not chosen:
            return {"match": False, "reason": "no_match", "rule_id": rid, "source_ip": sip or None}
        chosen["active"] = True
        chosen["any_source"] = not bool((chosen.get("source_ip") or "").strip())
        return {
            "match": True,
            "reason": "exact_source" if exact else "any_source",
            "rule_id": rid,
            "source_ip": sip or None,
            "suppression": chosen,
            "disposition": chosen.get("disposition"),
        }

    def suppression_suggestions(
        self,
        *,
        min_count: int = 2,
        days: int = 30,
        limit: int = 20,
    ) -> dict[str, Any]:
        """Rule_ids repeatedly closed as skippable — for analyst review, not auto-add."""
        min_count = max(2, int(min_count))
        days = max(1, int(days))
        limit = max(1, min(int(limit), 100))
        cutoff = datetime.now(timezone.utc).timestamp() - days * 86400
        tallies: dict[tuple[str, str], int] = {}
        with self._connect() as conn:
            rows = conn.execute(
                """
                SELECT rule_id, source_ip, analyst_disposition, approved, created_at
                FROM triage_feedback
                WHERE rule_id IS NOT NULL AND trim(rule_id) != ''
                """
            ).fetchall()
        for row in rows:
            ad = (row["analyst_disposition"] or "").strip().lower()
            if ad:
                if ad not in {"false_positive", "benign", "informational", "duplicate"}:
                    continue
            elif int(row["approved"] or 0) != 0:
                continue
            ts = self._parse_ts(str(row["created_at"] or ""))
            if ts is not None and ts < cutoff:
                continue
            rid = str(row["rule_id"] or "").strip()
            sip = str(row["source_ip"] or "").strip()
            key = (rid, sip)
            tallies[key] = tallies.get(key, 0) + 1
        suggestions = [
            {
                "rule_id": rid,
                "source_ip": sip or None,
                "any_source": not bool(sip),
                "count": n,
                "suggested_disposition": "informational",
            }
            for (rid, sip), n in sorted(tallies.items(), key=lambda x: (-x[1], x[0][0]))
            if n >= min_count
        ][:limit]
        return {
            "suggestions": suggestions,
            "count": len(suggestions),
            "min_count": min_count,
            "days": days,
        }

    def _suppression_row_active(
        self,
        row: dict[str, Any],
        *,
        now_ts: Optional[float] = None,
    ) -> bool:
        if (row.get("disabled_at") or "").strip():
            return False
        exp = (row.get("expires_at") or "").strip()
        if not exp:
            return True
        exp_ts = self._parse_ts(exp)
        if exp_ts is None:
            return True
        if now_ts is None:
            now_ts = datetime.now(timezone.utc).timestamp()
        return exp_ts >= now_ts

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
