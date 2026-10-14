import pytest

from app.explain import llm

_OPTIONAL_CONFIG = ("ANTHROPIC_API_KEY", "LLM_MODEL", "LLM_TIMEOUT_SECONDS", "LLM_MAX_TOKENS")


@pytest.fixture(autouse=True)
def isolated_configuration(monkeypatch):
    """Every test starts with the optional LLM integration off and an empty explanation cache."""
    for name in _OPTIONAL_CONFIG:
        monkeypatch.delenv(name, raising=False)
    llm.clear_cache()
    yield
    llm.clear_cache()
