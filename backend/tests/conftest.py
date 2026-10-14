import pytest

from app import reputation

_OPTIONAL_CONFIG = (
    "ORG_DOMAINS", "ORG_NAME", "ORG_ALIASES", "SAFE_BROWSING_API_KEY", "REPUTATION_TIMEOUT_SECONDS",
    "LLM_PROVIDER", "LLM_API_KEY", "ANTHROPIC_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_SECONDS", "LLM_EXPLANATIONS_ENABLED",
)


@pytest.fixture(autouse=True)
def isolated_configuration(monkeypatch):
    """Every test starts with optional integrations off and no cached provider state."""
    for name in _OPTIONAL_CONFIG:
        monkeypatch.delenv(name, raising=False)
    reputation.reset_state()
    yield
    reputation.reset_state()
