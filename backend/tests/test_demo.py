import pytest

from demo import run_demo

EXPECTED = {
    "legitimate": "LOW_RISK",
    "impersonation": "SUSPICIOUS",
    "url": "SUSPICIOUS",
    "attachment": "SUSPICIOUS",
    "content": "LOW_RISK",
    "bec": "LOW_RISK",  # documented limitation after removing combined indicators
    "upwind": "SUSPICIOUS",
    "full": "MALICIOUS",
}


@pytest.mark.parametrize("name", list(run_demo.SCENARIOS))
def test_demo_scenarios_run_offline_with_expected_verdicts(name, capsys):
    run_demo.run(name)
    assert f"Verdict: {EXPECTED[name]}" in capsys.readouterr().out
