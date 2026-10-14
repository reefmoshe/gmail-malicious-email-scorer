import pytest

from app.engine.models import Detection
from app.engine.scoring import decide_verdict, score
from app.engine.signals import CATEGORIES, SIGNALS


def _by_id(result):
    return {f.signal.id: f for f in result.findings}


def test_same_signal_counts_once_and_keeps_all_evidence():
    result = score([Detection("SENDER_REPLYTO_MISMATCH", ["a"]), Detection("SENDER_REPLYTO_MISMATCH", ["b", "a"])])
    f = _by_id(result)["SENDER_REPLYTO_MISMATCH"]
    assert f.counted_points == 8 and f.evidence == ["a", "b"]
    assert result.total == 8


def test_correlated_signals_count_only_the_strongest():
    result = score([Detection("SENDER_FREEMAIL_ORG_CLAIM", ["x"]), Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["y"])])
    findings = _by_id(result)
    assert findings["SENDER_BRAND_DISPLAY_MISMATCH"].counted_points == 10
    assert findings["SENDER_FREEMAIL_ORG_CLAIM"].score_status == "correlated"
    assert result.total == 10


def test_context_group_override_correlates_components_with_dmarc():
    result = score([Detection("AUTH_DMARC_FAIL", ["d"], group="dmarc"), Detection("AUTH_SPF_FAIL", ["s"], group="dmarc")])
    assert result.total == 25


def test_category_cap_is_applied_and_explained():
    result = score([Detection(s, ["e"]) for s in ("AUTH_DMARC_FAIL", "AUTH_SPF_FAIL", "AUTH_DKIM_FAIL")])
    assert result.category_scores["authentication"] == CATEGORIES["authentication"].cap == 30
    findings = _by_id(result)
    assert findings["AUTH_SPF_FAIL"].score_status == "capped" and findings["AUTH_SPF_FAIL"].counted_points == 5
    assert "capped" in findings["AUTH_SPF_FAIL"].note


def test_all_signals_together_respect_caps():
    result = score([Detection(s, ["e"]) for s in SIGNALS])
    assert result.category_scores["authentication"] <= 30
    assert result.category_scores["sender_identity"] <= 25
    assert result.total == 55


def test_no_detections_scores_zero():
    assert score([]).total == 0


@pytest.mark.parametrize("total, verdict", [(0, "LOW_RISK"), (29, "LOW_RISK"), (30, "SUSPICIOUS"), (69, "SUSPICIOUS"), (70, "MALICIOUS"), (100, "MALICIOUS")])
def test_verdict_thresholds(total, verdict):
    assert decide_verdict(total, [])[0] == verdict


def test_single_high_severity_finding_raises_floor_to_suspicious_only():
    result = score([Detection("SENDER_LOOKALIKE_DOMAIN", ["e"])])
    assert result.total == 15
    assert decide_verdict(result.total, result.findings)[0] == "SUSPICIOUS"


def test_single_low_or_medium_finding_stays_low_risk():
    for signal_id in ("SENDER_REPLYTO_MISMATCH", "AUTH_SPF_FAIL", "SENDER_FREEMAIL_ORG_CLAIM", "AUTH_DKIM_NONE"):
        result = score([Detection(signal_id, ["e"])])
        assert decide_verdict(result.total, result.findings)[0] == "LOW_RISK", signal_id


def test_correlated_high_severity_finding_does_not_raise_floor():
    result = score([Detection("AUTH_DMARC_FAIL", ["d"]), Detection("SENDER_REPLYTO_MISMATCH", ["r"])])
    assert decide_verdict(result.total, result.findings)[0] == "SUSPICIOUS"
    weak = score([Detection("SENDER_REPLYTO_LOOKALIKE", ["l"], group="x"), Detection("SENDER_REPLYTO_MISMATCH", ["m"], group="x")])
    assert _by_id(weak)["SENDER_REPLYTO_MISMATCH"].counted_points == 0
