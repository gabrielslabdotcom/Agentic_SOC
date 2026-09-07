"""Discord webhook notifications for Agentic SOC."""

from __future__ import annotations

from typing import Any, Optional

import httpx

from agentic_soc.config import Settings, get_settings


def _clip(value: Any, limit: int = 1024) -> str:
    text = str(value if value is not None else "—").strip() or "—"
    if len(text) <= limit:
        return text
    return text[: max(0, limit - 1)] + "…"


def _field(name: str, value: Any, *, inline: bool = False, limit: int = 1024) -> dict[str, Any]:
    return {"name": name, "value": _clip(value, limit), "inline": inline}


class DiscordNotifier:
    """Send lab SOC alerts to a Discord channel via incoming webhook."""

    def __init__(self, settings: Optional[Settings] = None) -> None:
        self.settings = settings or get_settings()

    @property
    def configured(self) -> bool:
        return bool((self.settings.discord_webhook_url or "").strip())

    async def send_raw(self, content: str = "", *, embeds: Optional[list[dict[str, Any]]] = None) -> dict[str, Any]:
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
            }
        return {"ok": True, "status_code": resp.status_code}

    async def notify_case_opened(self, case: dict[str, Any]) -> dict[str, Any]:
        """Notify when autonomy opens a case that needs human approval."""
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
        if snippet:
            snippet = " ".join(snippet.split())

        approve_cmd = (
            f"python scripts/approve_case.py --case-id {case_id} --approve "
            f'--note "reviewed from Discord"'
        )
        reject_cmd = (
            f"python scripts/approve_case.py --case-id {case_id} --reject "
            f'--note "noise / not actionable"'
        )
        next_steps = case.get("analyst_next_steps") or (
            "1) Confirm alert in Wazuh dashboard\n"
            "2) Review IOCs / full_log below\n"
            "3) Record Approve or Reject (see labels) — no containment runs"
        )
        decision_legend = (
            "**Approve** records that you accept the triage "
            "(disposition + recommended action) as the investigation outcome. "
            "Case status becomes `approved`; a note is stored. "
            "**No firewall, isolation, or other containment is executed.**\n"
            "**Reject** records that this is noise, a duplicate, or the proposal is wrong. "
            "Case status becomes `rejected`; a note is stored. "
            "**Also does not execute containment.**"
        )

        fields = [
            _field("Disposition", case.get("disposition"), inline=True),
            _field("Severity", severity, inline=True),
            _field("Confidence", case.get("confidence") or "—", inline=True),
            _field("Why opened", why, inline=False, limit=900),
            _field("Rule", rule_line, inline=True),
            _field("When", case.get("timestamp") or "—", inline=True),
            _field("Agent", case.get("agent_name") or "—", inline=True),
            _field("Alert id", f"`{case.get('alert_id') or '—'}`", inline=True),
            _field("IOCs", ioc_text, inline=False, limit=900),
            _field("VirusTotal", vt_text, inline=False, limit=500),
            _field(
                "Recommended action",
                case.get("recommended_action") or "investigate_and_document",
                inline=False,
            ),
            _field("Analyst next steps", next_steps, inline=False, limit=900),
            _field("What Approve / Reject records", decision_legend, inline=False, limit=1024),
            _field(
                "Approve (CLI)",
                "Accept triage & document — status=`approved`, note only.\n"
                f"`{approve_cmd}`",
                inline=False,
                limit=900,
            ),
            _field(
                "Reject (CLI)",
                "Mark noise / decline proposal — status=`rejected`, note only.\n"
                f"`{reject_cmd}`",
                inline=False,
                limit=900,
            ),
        ]
        if snippet:
            fields.append(_field("Log snippet", f"```{snippet[:900]}```", inline=False, limit=1000))

        embed = {
            "title": f"SOC case opened #{case_id}",
            "description": _clip(title, 500),
            "color": color,
            "fields": fields[:25],
            "footer": {
                "text": "Lab autonomy — containment NOT executed. Use approve_case.py.",
            },
        }
        return await self.send_raw(
            content="**Pending human approval** — review context below, then approve/reject.",
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
                        "Review with `approve_case.py`."
                    )
                )
            )
        ok = all(r.get("ok") for r in results if "skipped" not in r)
        return {"ok": ok, "notifications": len(results)}
