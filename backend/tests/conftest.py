import pytest

_OPTIONAL_CONFIG = ("ANTHROPIC_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_SECONDS")


@pytest.fixture(autouse=True)
def isolated_configuration(monkeypatch):
    """Every test starts with the optional LLM integration switched off."""
    for name in _OPTIONAL_CONFIG:
        monkeypatch.delenv(name, raising=False)
