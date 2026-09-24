from pathlib import Path
import os
import socket

from pydantic_settings import BaseSettings, SettingsConfigDict

# Repo root (…/Agentic_SOC), so MCP/stdio launches find .env regardless of cwd
_REPO_ROOT = Path(__file__).resolve().parents[2]
_ENV_FILE = _REPO_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=str(_ENV_FILE) if _ENV_FILE.exists() else ".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    wazuh_api_url: str = "https://192.168.50.254:55000"
    wazuh_api_user: str = "wazuh-wui"
    wazuh_api_password: str = "MyS3cr37P450r.*-"
    wazuh_api_verify_ssl: bool = False

    wazuh_indexer_url: str = "https://192.168.50.254:9200"
    wazuh_indexer_user: str = "admin"
    wazuh_indexer_password: str = "SecretPassword"
    wazuh_indexer_verify_ssl: bool = False

    # Browser link for analysts (not an API endpoint)
    wazuh_dashboard_url: str = "https://192.168.50.254"

    cases_db_path: str = "data/cases.sqlite"

    abuseipdb_api_key: str = ""
    virustotal_api_key: str = ""
    discord_webhook_url: str = ""
    # Gateway bot (outbound WS on Pop). Prefer over webhook for case-opened buttons.
    # Never commit real token values — set on Pop .env only.
    discord_bot_token: str = ""
    discord_channel_id: str = ""
    discord_guild_id: str = ""

    # Optional Cursor cloud investigation (Mac-offline / Pop autonomy hook)
    # Install: pip install -e '.[cursor]'  — disabled until AUTONOMY_CURSOR_AGENT=true
    cursor_api_key: str = ""
    autonomy_cursor_agent: bool = False
    cursor_agent_model: str = "composer-2.5"
    cursor_agent_repo: str = ""
    cursor_agent_starting_ref: str = "main"
    # If the GitHub App cannot see CURSOR_AGENT_REPO, retry as no-repo (case payload only).
    cursor_agent_norepo_fallback: bool = True
    # Public URL the cloud agent can PATCH (e.g. tunnel) or http://127.0.0.1:8080
    # when using a self-hosted pool worker on Pop.
    agentic_soc_api_url: str = ""
    # Optional self-hosted pool name (CloudAgentOptions.env type=pool)
    cursor_cloud_pool: str = ""

    # OpenAI-compatible chat (connector catalog). Empty until that connector is enabled.
    openai_base_url: str = ""
    openai_api_key: str = ""
    openai_model: str = "gpt-4o-mini"
    # cursor | openai | empty. Set by the connector store when a file exists.
    llm_connector: str = ""

    # Analyst UI instance: pop-live | mac-local | empty (auto-detect from cases path)
    agentic_soc_instance: str = ""

    @property
    def cases_path(self) -> Path:
        path = Path(self.cases_db_path)
        if not path.is_absolute():
            return _REPO_ROOT / path
        return path

    def resolve_instance(self) -> str:
        """Return pop-live or mac-local for the analyst dashboard banner."""
        explicit = (self.agentic_soc_instance or os.environ.get("AGENTIC_SOC_INSTANCE") or "").strip().lower()
        if explicit in {"pop-live", "mac-local"}:
            return explicit
        path = str(self.cases_path)
        if path.startswith("/home/admin/Agentic_SOC") or "/home/admin/Agentic_SOC/" in path:
            return "pop-live"
        return "mac-local"


def hostname() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return "unknown"


def get_settings() -> Settings:
    """Load ``.env``, then overlay ``data/connectors.json`` when that file exists.

    Appliance mode with no saved Wazuh blanks the lab host defaults so the
    poller cannot reach ``192.168.50.254`` before the wizard.
    """
    base = Settings()
    from agentic_soc.connectors import apply_store

    return apply_store(base)
