from pathlib import Path

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

    @property
    def cases_path(self) -> Path:
        path = Path(self.cases_db_path)
        if not path.is_absolute():
            return _REPO_ROOT / path
        return path


def get_settings() -> Settings:
    return Settings()
