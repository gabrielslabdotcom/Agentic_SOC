"""Discord notifications for Agentic SOC (Gateway bot preferred, webhook fallback)."""

from __future__ import annotations

from typing import Any, Optional
from urllib.parse import urlparse

import httpx

from agentic_soc.analyst_outcomes import (
    ANALYST_DISPOSITIONS,
    BENIGN,
    CONFIRMED_COMPROMISE,
    DUPLICATE,
    FALSE_POSITIVE,
    INFORMATIONAL,
    OUTCOME_META,
)
from agentic_soc.config import Settings, get_settings

# Discord button styles: 1 primary, 2 secondary, 3 success, 4 danger
_BUTTON_STYLE = {
    FALSE_POSITIVE: 2,
    BENIGN: 2,
    INFORMATIONAL: 2,
    DUPLICATE: 2,
    CONFIRMED_COMPROMISE: 4,
}

CUSTOM_ID_PREFIX = "soc"


def parse_outcome_custom_id(custom_id: str) -> tuple[str, int]:
    """Parse ``soc:{disposition}:{case_id}`` → (disposition, case_id)."""
    raw = (custom_id or "").strip()
    parts = raw.split(":")
    if len(parts) != 3 or parts[0] != CUSTOM_ID_PREFIX:
        raise ValueError(f"invalid outcome custom_id: {custom_id!r}")
    disposition = parts[1].strip().lower()
    if disposition not in ANALYST_DISPOSITIONS:
        raise ValueError(f"unknown disposition in custom_id: {disposition!r}")
    try:
        case_id = int(parts[2])
    except ValueError as exc:
        raise ValueError(f"invalid case_id in custom_id: {custom_id!r}") from exc
    if case_id < 1:
        raise ValueError(f"invalid case_id {case_id} (must be >= 1)")
    return disposition, case_id


def outcome_custom_id(disposition: str, case_id: int) -> str:
    disposition = (disposition or "").strip().lower()
    if disposition not in ANALYST_DISPOSITIONS:
        raise ValueError(f"unknown disposition: {disposition!r}")
    cid = int(case_id)
    if cid < 1:
        raise ValueError(f"invalid case_id {cid} (must be >= 1)")
    return f"{CUSTOM_ID_PREFIX}:{disposition}:{cid}"


def build_outcome_components(case_id: int) -> list[dict[str, Any]]:
    """ActionRows of analyst-outcome buttons for a case-opened message."""
    if int(case_id) < 1:
        raise ValueError(f"invalid case_id {case_id} (must be >= 1)")
    order = (
        FALSE_POSITIVE,
        BENIGN,
        INFORMATIONAL,
        DUPLICATE,
        CONFIRMED_COMPROMISE,
    )
    # Discord allows max 5 buttons per row; we fit all five in one row.
    buttons = []
    for disposition in order:
        meta = OUTCOME_META[disposition]
        buttons.append(
            {
                "type": 2,  # BUTTON
                "style": _BUTTON_STYLE.get(disposition, 2),
                "label": meta["label"][:80],
                "custom_id": outcome_custom_id(disposition, case_id),
            }
        )
    return [{"type": 1, "components": buttons}]  # ACTION_ROW


def _clip(value: Any, limit: int = 1024) -> str:
    text = str(value if value is not None else "—").strip() or "—"
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _field(name: str, value: Any, *, inline: bool = False, limit: int = 1024) -> dict[str, Any]:
    return {"name": name, "value": _clip(value, limit), "inline": inline}


def analyst_ui_base_url(settings: Settings) -> str:
    """Derive http://<host>:8080 from dashboard/API settings (no secrets)."""
    for raw in (
        getattr(settings, "agentic_soc_api_url", "") or "",
        settings.wazuh_dashboard_url or "",
        settings.wazuh_api_url or "",
    ):
        text = str(raw).strip()
        if not text:
            continue
        parsed = urlparse(text if "://" in text else f"http://{text}")
        host = parsed.hostname
        if host:
            return f"http://{host}:8080"
    return "http://127.0.0.1:8080"


class DiscordNotifier:
    """Send lab SOC alerts via Gateway bot REST (buttons) or incoming webhook."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    @property
    def bot_configured(self) -> bool:
        token = (self.settings.discord_bot_token or "").strip()
        channel = (self.settings.discord_channel_id or "").strip()
        return bool(token and channel)

    @property
    def webhook_configured(self) -> bool:
        return bool((self.settings.discord_webhook_url or "").strip())

    @property
    def configured(self) -> bool:
        return self.bot_configured or self.webhook_configured

    async def send_raw(
        self,
        content: str = "",
        *,
        embeds: Optional[list[dict[str, Any]]] = None,
        components: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        """Send via bot channel REST when configured; else webhook (no components)."""
        if self.bot_configured:
            return await self._send_bot(
                content=content, embeds=embeds, components=components
            )
        return await self._send_webhook(content=content, embeds=embeds)

    async def _send_bot(
        self,
        *,
        content: str = "",
        embeds: Optional[list[dict[str, Any]]] = None,
        components: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        token = (self.settings.discord_bot_token or "").strip()
        channel_id = (self.settings.discord_channel_id or "").strip()
        if not token or not channel_id:
            return {"ok": False, "error": "DISCORD_BOT_TOKEN / DISCORD_CHANNEL_ID not set"}

        payload: dict[str, Any] = {}
        if content:
            payload["content"] = content[:1900]
        if embeds:
            payload["embeds"] = embeds[:10]
        if components:
            payload["components"] = components[:5]

        url = f"https://discord.com/api/v10/channels/{channel_id}/messages"
        headers = {
            "Authorization": f"Bot {token}",
            "Content-Type": "application/json",
        }
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload, headers=headers)
        if resp.status_code >= 400:
            return {
                "ok": False,
                "status_code": resp.status_code,
                "error": (resp.text or "")[:300],
                "via": "bot",
            }
        data: dict[str, Any] = {}
        try:
            data = resp.json()
        except Exception:
            data = {}
        return {
            "ok": True,
            "status_code": resp.status_code,
            "via": "bot",
            "message_id": data.get("id"),
            "channel_id": data.get("channel_id") or channel_id,
        }

    async def _send_webhook(
        self,
        *,
        content: str = "",
        embeds: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        url = (self.settings.discord_webhook_url or "").strip()
        if not url:
            return {"ok": False, "error": "DISCORD_WEBHOOK_URL not set"}

        payload: dict[str, Any] = {}
        if content:
            payload["content"] = content[:1900]
        if embeds:
            payload["embeds"] = embeds[:10]

        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.post(url, json=payload)
        if resp.status_code >= 400:
            return {
                "ok": False,
                "status_code": resp.status_code,
                "error": (resp.text or "")[:300],
                "via": "webhook",
            }
        return {"ok": True, "status_code": resp.status_code, "via": "webhook"}

    def _case_opened_embed(self, case: dict[str, Any]) -> dict[str, Any]:
        severity = str(case.get("severity") or "medium").lower()
        color = {
            "critical": 0xE74C3C,
            "high": 0xE67E22,
            "medium": 0xF1C40F,
            "low": 0x95A5A6,
        }.get(severity, 0x3498DB)

        case_id = case.get("id")
        title = case.get("title") or f"Case #{case_id}"
        reasons = case.get("reasons") or []
        if isinstance(reasons, str):
            why = reasons
        else:
            why = "; ".join(str(r) for r in reasons if r) or "triage gate opened case"

        rule_id = case.get("rule_id") or "—"
        rule_level = case.get("rule_level")
        rule_line = f"`{rule_id}` level {rule_level}" if rule_level is not None else f"`{rule_id}`"

        iocs = case.get("iocs") or []
        if isinstance(iocs, list) and iocs:
            ioc_bits = []
            for item in iocs[:6]:
                if isinstance(item, dict):
                    ioc_bits.append(f"{item.get('ioc_type', 'ioc')}:{item.get('ioc')}")
                else:
                    ioc_bits.append(str(item))
            ioc_text = ", ".join(ioc_bits)
        else:
            src = case.get("source_ip")
            ioc_text = f"source_ip:{src}" if src else "none extracted"

        enrichments = case.get("enrichments") or []
        if isinstance(enrichments, list) and enrichments:
            vt_bits = []
            for e in enrichments[:4]:
                if not isinstance(e, dict):
                    continue
                if e.get("error"):
                    vt_bits.append(f"{e.get('ioc')}: error")
                else:
                    vt_bits.append(
                        f"{e.get('ioc')}: mal={e.get('malicious')} sus={e.get('suspicious')}"
                    )
            vt_text = "; ".join(vt_bits) if vt_bits else "none"
        else:
            vt_text = "none / skipped"

        snippet = (case.get("full_log") or case.get("log_snippet") or "").strip()
        brief = case.get("brief") if isinstance(case.get("brief"), dict) else {}
        actors = brief.get("actors") if isinstance(brief.get("actors"), dict) else {}
        evidence = (brief.get("evidence") or snippet or "").strip()
        if evidence:
            evidence = " ".join(evidence.split())
        why_bits = brief.get("why") if isinstance(brief.get("why"), list) else None
        if why_bits:
            why = "; ".join(str(r) for r in why_bits if r) or why
        do_next = brief.get("do_next") if isinstance(brief.get("do_next"), list) else []
        next_steps = str(case.get("analyst_next_steps") or "Review in the analyst UI. Do not execute containment.")
        if do_next:
            next_steps = "\n".join(f"{i}. {step}" for i, step in enumerate(do_next, start=1))
        source = actors.get("source_ip") or case.get("source_ip") or "—"
        user = actors.get("user") or case.get("user") or "—"
        agent = actors.get("agent") or case.get("agent_name") or "—"
        vt_from_brief = (brief.get("vt") or "").strip()
        if vt_from_brief:
            vt_text = vt_from_brief

        ui_url = analyst_ui_base_url(self.settings)
        wazuh = (brief.get("wazuh_url") or "").strip()
        fields = [
            _field("Disposition", case.get("disposition"), inline=True),
            _field("Severity", severity, inline=True),
            _field("Source", source, inline=True),
            _field("User", user, inline=True),
            _field("Agent", agent, inline=True),
            _field("Rule", rule_line, inline=True),
            _field("When", case.get("timestamp") or "—", inline=True),
            _field("Why", why, inline=False, limit=500),
        ]
        if evidence:
            fields.append(_field("Evidence", f"`{_clip(evidence, 180)}`", inline=False, limit=220))
        if vt_text and vt_text not in ("none", "none / skipped"):
            fields.append(_field("VirusTotal", vt_text, inline=False, limit=300))
        fields.append(
            _field(
                "Recommended",
                case.get("recommended_action") or brief.get("recommended_action") or "investigate_and_document",
                inline=False,
                limit=200,
            )
        )
        open_bits = f"[Analyst UI]({ui_url}/)"
        if wazuh:
            open_bits += f" · [Wazuh]({wazuh})"
        fields.append(_field("Open", open_bits, inline=False, limit=300))
        fields.append(_field("Do next", next_steps, inline=False, limit=900))

        footer_text = (
            "Propose only — outcome buttons record the decision. Containment is not executed."
        )
        headline = brief.get("headline") or title
        return {
            "title": f"SOC case opened #{case_id}",
            "description": _clip(headline, 300),
            "color": color,
            "fields": fields[:25],
            "footer": {"text": footer_text},
        }

    async def notify_case_opened(self, case: dict[str, Any]) -> dict[str, Any]:
        """Notify when autonomy opens a case that needs human approval."""
        embed = self._case_opened_embed(case)
        case_id = case.get("id")
        components: Optional[list[dict[str, Any]]] = None
        if self.bot_configured and case_id is not None:
            try:
                cid = int(case_id)
                if cid >= 1:
                    components = build_outcome_components(cid)
            except (TypeError, ValueError):
                components = None
        return await self.send_raw(
            content="**Pending human review** — record an analyst outcome (no containment).",
            embeds=[embed],
            components=components,
        )

    async def notify_severity_rose(
        self,
        case: dict[str, Any],
        *,
        previous: str,
        current: str,
    ) -> dict[str, Any]:
        """Page only when an attached alert raises the open incident's severity."""
        case_id = case.get("id")
        severity = str(current or "medium").lower()
        color = {
            "critical": 0xE74C3C,
            "high": 0xE67E22,
            "medium": 0xF1C40F,
            "low": 0x95A5A6,
        }.get(severity, 0xE67E22)
        ui_url = analyst_ui_base_url(self.settings)
        embed = {
            "title": f"Incident #{case_id} severity rose",
            "description": _clip(f"{previous or '—'} → {current or '—'}", 200),
            "color": color,
            "fields": [
                _field("Source", case.get("source_ip") or "—", inline=True),
                _field("User", case.get("user") or "—", inline=True),
                _field("Rule", case.get("rule_id") or "—", inline=True),
                _field("Open", f"[Analyst UI]({ui_url}/)", inline=False, limit=200),
            ],
            "footer": {"text": "Same incident. Propose only — containment is not executed."},
        }
        components = None
        if self.bot_configured and case_id is not None:
            try:
                cid = int(case_id)
                if cid >= 1:
                    components = build_outcome_components(cid)
            except (TypeError, ValueError):
                components = None
        return await self.send_raw(
            content="**Severity rose** on an open incident — review the new alert. No containment.",
            embeds=[embed],
            components=components,
        )

    async def notify_investigation_ready(
        self,
        case: dict[str, Any],
        *,
        note: str,
        outcome: Optional[dict[str, Any]] = None,
    ) -> dict[str, Any]:
        """Follow-up when the Cursor cloud note has been written to the case."""
        outcome = outcome or {}
        case_id = case.get("id")
        title = case.get("title") or f"Case #{case_id}"
        preview = (note or "").strip()
        if preview.startswith("[cursor_investigation]"):
            parts = preview.split("\n\n", 1)
            preview = parts[1] if len(parts) > 1 else preview
        preview = " ".join(preview.split())
        ui_url = analyst_ui_base_url(self.settings)
        embed = {
            "title": f"Investigation note ready #{case_id}",
            "description": _clip(title, 400),
            "color": 0x5B8DEF,
            "fields": [
                _field("Disposition", case.get("disposition"), inline=True),
                _field("Severity", case.get("severity"), inline=True),
                _field("run_id", f"`{outcome.get('run_id') or '—'}`", inline=True),
                _field("Note preview", preview or "(empty)", inline=False, limit=900),
                _field(
                    "Next",
                    f"Open {ui_url}/, read the Cursor investigation section, then "
                    "record False Positive / Benign / Informational / Duplicate / "
                    "Confirmed Compromise (record-only — no containment).",
                    inline=False,
                    limit=500,
                ),
            ],
            "footer": {
                "text": "Lab autonomy — note stored on the case. Containment NOT executed.",
            },
        }
        return await self.send_raw(
            content=f"**Cursor investigation landed on case #{case_id}** — still needs a human closing outcome.",
            embeds=[embed],
        )

    async def notify_cycle_summary(
        self,
        *,
        opened: int,
        skipped: int,
        fetched: int,
        cases: Optional[list[dict[str, Any]]] = None,
    ) -> dict[str, Any]:
        if opened <= 0:
            return {"ok": True, "skipped": "no_cases"}
        # Prefer per-case embeds; fall back to one summary
        results = []
        for case in (cases or [])[:5]:
            results.append(await self.notify_case_opened(case))
        if not cases:
            results.append(
                await self.send_raw(
                    content=(
                        f"**Autonomy cycle:** opened **{opened}** case(s), "
                        f"skipped {skipped}, fetched {fetched}. "
                        "Review with outcome buttons or `approve_case.py`."
                    )
                )
            )
        ok = all(r.get("ok") for r in results if "skipped" not in r)
        return {"ok": ok, "notifications": len(results)}
