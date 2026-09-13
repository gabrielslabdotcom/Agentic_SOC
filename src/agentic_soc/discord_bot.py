"""Discord Gateway bot for analyst-outcome buttons (outbound websocket only)."""

from __future__ import annotations

import logging
from typing import Any, Optional

from agentic_soc.analyst_outcomes import OUTCOME_META
from agentic_soc.cases import CaseStore
from agentic_soc.config import Settings, get_settings
from agentic_soc.discord_notify import parse_outcome_custom_id

LOG = logging.getLogger(__name__)


def _discord_author(user: Any) -> str:
    if user is None:
        return "discord:unknown"
    name = getattr(user, "name", None) or getattr(user, "display_name", None) or "unknown"
    uid = getattr(user, "id", None)
    if uid is not None:
        return f"discord:{name}:{uid}"
    return f"discord:{name}"


def handle_outcome_click(
    store: CaseStore,
    *,
    custom_id: str,
    user: Any = None,
) -> dict[str, Any]:
    """
    Apply an analyst outcome from a Discord button custom_id.

    Returns a small result dict for ephemeral replies (ok / error).
    Never executes containment.
    """
    try:
        disposition, case_id = parse_outcome_custom_id(custom_id)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    case = store.get_case(case_id)
    if case.get("error"):
        return {"ok": False, "error": f"case #{case_id} not found", "case_id": case_id}

    status = (case.get("status") or "").strip().lower()
    # Match CaseStore.resolve_proposals: only status=open is actionable.
    if status != "open":
        label = OUTCOME_META.get(status, {}).get("label") or status or "unknown"
        return {
            "ok": False,
            "error": f"case #{case_id} already closed as {label}",
            "case_id": case_id,
            "status": status,
        }

    author = _discord_author(user)
    display = getattr(user, "name", None) or getattr(user, "display_name", None) or "unknown"
    note = f"closed from Discord by {display}"
    updated = store.resolve_proposal(
        case_id,
        disposition=disposition,
        note=note,
        author=author,
    )
    if updated.get("error"):
        return {"ok": False, "error": str(updated["error"]), "case_id": case_id}

    label = OUTCOME_META.get(disposition, {}).get("label") or disposition
    return {
        "ok": True,
        "case_id": case_id,
        "disposition": disposition,
        "label": label,
        "author": author,
        "case": updated,
    }


def interaction_allowed(
    settings: Settings,
    *,
    guild_id: Optional[int],
    channel_id: Optional[int],
) -> tuple[bool, str]:
    """Enforce optional guild allowlist and required channel id."""
    expected_channel = (settings.discord_channel_id or "").strip()
    if expected_channel:
        if channel_id is None or str(channel_id) != expected_channel:
            return False, "interaction ignored (wrong channel)"
    expected_guild = (settings.discord_guild_id or "").strip()
    if expected_guild:
        if guild_id is None or str(guild_id) != expected_guild:
            return False, "interaction ignored (wrong guild)"
    return True, ""


def build_client(
    settings: Optional[Settings] = None,
    *,
    store: Optional[CaseStore] = None,
    discord_module: Any = None,
) -> Any:
    """
    Construct a discord.py Client with outcome-button handlers.

    ``discord_module`` is injectable for unit tests (avoids requiring discord.py
    at import time for non-bot code paths).
    """
    settings = settings or get_settings()
    if discord_module is None:
        import discord  # type: ignore

        discord_module = discord

    token = (settings.discord_bot_token or "").strip()
    if not token:
        raise RuntimeError("DISCORD_BOT_TOKEN is not set")

    intents = discord_module.Intents.none()
    intents.guilds = True
    client = discord_module.Client(intents=intents)
    case_store = store or CaseStore(settings.cases_path)

    @client.event
    async def on_ready() -> None:
        LOG.info(
            "discord bot ready as %s (guilds=%s)",
            getattr(client.user, "name", client.user),
            len(client.guilds),
        )

    @client.event
    async def on_interaction(interaction: Any) -> None:
        # ComponentType.button == 2; InteractionType.component == 3
        itype = getattr(interaction, "type", None)
        type_val = getattr(itype, "value", itype)
        if type_val != 3:
            return
        data = getattr(interaction, "data", None) or {}
        custom_id = ""
        if isinstance(data, dict):
            custom_id = str(data.get("custom_id") or "")
        else:
            custom_id = str(getattr(data, "custom_id", "") or "")
        if not custom_id.startswith("soc:"):
            return

        guild = getattr(interaction, "guild", None)
        channel = getattr(interaction, "channel", None)
        guild_id = getattr(guild, "id", None) or getattr(interaction, "guild_id", None)
        channel_id = getattr(channel, "id", None) or getattr(interaction, "channel_id", None)
        ok, reason = interaction_allowed(
            settings, guild_id=guild_id, channel_id=channel_id
        )
        if not ok:
            LOG.warning("%s custom_id=%s", reason, custom_id)
            try:
                await interaction.response.send_message(reason, ephemeral=True)
            except Exception:
                LOG.exception("failed to send allowlist rejection")
            return

        user = getattr(interaction, "user", None) or getattr(interaction, "member", None)
        result = handle_outcome_click(case_store, custom_id=custom_id, user=user)
        if not result.get("ok"):
            try:
                await interaction.response.send_message(
                    f"Could not close case: {result.get('error')}",
                    ephemeral=True,
                )
            except Exception:
                LOG.exception("failed to send error ephemeral")
            return

        label = result.get("label") or result.get("disposition")
        case_id = result.get("case_id")
        try:
            await interaction.response.send_message(
                f"Recorded **{label}** on case #{case_id} (no containment).",
                ephemeral=True,
            )
        except Exception:
            LOG.exception("failed to send success ephemeral")

        # Edit original message: footer + clear buttons
        message = getattr(interaction, "message", None)
        if message is not None:
            try:
                embeds = list(getattr(message, "embeds", []) or [])
                if embeds:
                    emb = embeds[0]
                    # discord.Embed.copy() exists; fall back to to_dict mutate
                    if hasattr(emb, "copy"):
                        new_emb = emb.copy()
                        new_emb.set_footer(
                            text=f"Closed as {label} by {_discord_author(user)} — containment NOT executed."
                        )
                        await message.edit(embed=new_emb, view=None)
                    else:
                        await message.edit(components=[], content=getattr(message, "content", None))
                else:
                    await message.edit(view=None)
            except Exception:
                LOG.exception("failed to edit Discord message after close")

    return client


def run_bot(
    settings: Optional[Settings] = None,
    *,
    store: Optional[CaseStore] = None,
) -> None:
    """Blocking entry: connect Gateway and process interactions until stopped."""
    settings = settings or get_settings()
    token = (settings.discord_bot_token or "").strip()
    if not token:
        raise SystemExit("DISCORD_BOT_TOKEN is not set in environment / .env")
    if not (settings.discord_channel_id or "").strip():
        LOG.warning("DISCORD_CHANNEL_ID unset — channel allowlist disabled")

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    client = build_client(settings, store=store)
    client.run(token)
