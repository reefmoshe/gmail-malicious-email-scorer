import pytest

from app.engine.models import Detection
from app.engine.scoring import decide_verdict, score
from app.engine.signals import CATEGORIES, SIGNALS


def _by_id(result):
    return {f.signal.id: f for f in result.findings}


def test_same_signal_counts_once_and_keeps_all_evidence():
    result = score([Detection("SENDER_REPLYTO_MISMATCH", ["a"]), Detection("SENDER_REPLYTO_MISMATCH", ["b", "a"])])
    f = _by_id(result)["SENDER_REPLYTO_MISMATCH"]
    assert f.counted_points == 6 and f.evidence == ["a", "b"]
    assert result.total == 6


def test_correlated_signals_count_only_the_strongest():
    result = score([Detection("SENDER_FREEMAIL_ORG_CLAIM", ["x"]), Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["y"])])
    findings = _by_id(result)
    assert findings["SENDER_FREEMAIL_ORG_CLAIM"].counted_points == 12
    assert findings["SENDER_BRAND_DISPLAY_MISMATCH"].score_status == "correlated"
    assert result.total == 12


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
    assert result.category_scores["sender_identity"] <= 45
    assert result.category_scores["urls"] <= 35
    assert sum(result.category_scores.values()) == 30 + 45 + 35 + 35 + 15 + 20
    assert result.total == 100  # final score capped at 100


def test_no_detections_scores_zero():
    assert score([]).total == 0


@pytest.mark.parametrize("total, verdict", [(0, "LOW_RISK"), (29, "LOW_RISK"), (30, "SUSPICIOUS"), (69, "SUSPICIOUS"), (70, "MALICIOUS"), (100, "MALICIOUS")])
def test_verdict_thresholds(total, verdict):
    assert decide_verdict(total, [])[0] == verdict


def test_single_high_severity_finding_raises_floor_to_suspicious_only():
    result = score([Detection("SENDER_REPLYTO_LOOKALIKE", ["e"])])
    assert result.total == 20
    verdict, reason = decide_verdict(result.total, result.findings)
    assert verdict == "SUSPICIOUS" and "high-severity" in reason


def test_lookalike_domain_alone_is_suspicious_by_score():
    result = score([Detection("SENDER_LOOKALIKE_DOMAIN", ["e"], subjects=frozenset({"BrandX"}))])
    assert result.total == 35
    verdict, reason = decide_verdict(result.total, result.findings)
    assert verdict == "SUSPICIOUS" and "threshold" in reason


def test_single_low_or_medium_finding_stays_low_risk():
    for signal_id in ("SENDER_REPLYTO_MISMATCH", "AUTH_SPF_FAIL", "SENDER_FREEMAIL_ORG_CLAIM", "AUTH_DKIM_NONE"):
        result = score([Detection(signal_id, ["e"])])
        assert decide_verdict(result.total, result.findings)[0] == "LOW_RISK", signal_id


def test_correlated_high_severity_finding_does_not_raise_floor():
    result = score([Detection("AUTH_DMARC_FAIL", ["d"]), Detection("SENDER_REPLYTO_MISMATCH", ["r"])])
    assert decide_verdict(result.total, result.findings)[0] == "SUSPICIOUS"
    weak = score([Detection("SENDER_REPLYTO_LOOKALIKE", ["l"], group="x"), Detection("SENDER_REPLYTO_MISMATCH", ["m"], group="x")])
    assert _by_id(weak)["SENDER_REPLYTO_MISMATCH"].counted_points == 0


# --- Reinforcement (generic: brand names below are placeholders, not special cases) -----

def _brand(name):
    return frozenset({name})


def test_display_claim_about_the_same_brand_only_reinforces():
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["n"], subjects=_brand("BrandX")),
    ])
    display = _by_id(result)["SENDER_BRAND_DISPLAY_MISMATCH"]
    assert (display.counted_points, display.score_status) == (5, "reinforcing")
    assert "BrandX" in display.note
    assert result.total == 40


def test_display_claim_about_a_different_brand_counts_in_full():
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["n"], subjects=_brand("BrandY")),
    ])
    assert _by_id(result)["SENDER_BRAND_DISPLAY_MISMATCH"].counted_points == 10
    assert result.total == 45


def test_display_claim_naming_an_extra_brand_is_not_reduced():
    """Reinforcement only when every brand the weaker finding names is already covered."""
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["n"], subjects=frozenset({"BrandX", "BrandY"})),
    ])
    assert _by_id(result)["SENDER_BRAND_DISPLAY_MISMATCH"].counted_points == 10


def test_findings_without_brand_subjects_are_independent():
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_DISPLAY_HAS_ADDRESS", ["address of an unprotected domain"]),
    ])
    assert _by_id(result)["SENDER_DISPLAY_HAS_ADDRESS"].counted_points == 10
    assert result.total == 45


def test_signals_without_reinforcing_weight_are_never_reduced():
    """The Reply-To look-alike is not a display claim: it keeps its full weight."""
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_REPLYTO_LOOKALIKE", ["r"], subjects=_brand("BrandX")),
    ])
    assert _by_id(result)["SENDER_REPLYTO_LOOKALIKE"].score_status == "capped"  # 35 + 20 > 45
    assert result.category_scores["sender_identity"] == 45


def test_reinforcing_then_capped_keeps_both_explanations():
    result = score([
        Detection("SENDER_LOOKALIKE_DOMAIN", ["d"], subjects=_brand("BrandX")),
        Detection("SENDER_REPLYTO_LOOKALIKE", ["r"], subjects=_brand("BrandZ")),
        Detection("SENDER_BRAND_DISPLAY_MISMATCH", ["n"], subjects=_brand("BrandX")),
    ])
    display = _by_id(result)["SENDER_BRAND_DISPLAY_MISMATCH"]
    assert display.counted_points == 0 and display.score_status == "capped"
    assert "Reinforces" in display.note and "capped" in display.note
    assert result.category_scores["sender_identity"] == 45
