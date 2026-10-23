from __future__ import annotations

from app.services.risk_engine import RiskEngine, band_for, severity_for_score


def test_bands_cover_full_range():
    assert band_for(0)[0] == "informational"
    assert band_for(19)[0] == "informational"
    assert band_for(20)[0] == "guarded"
    assert band_for(59)[0] == "medium"
    assert band_for(60)[0] == "high"
    assert band_for(80)[0] == "critical"
    assert band_for(100)[0] == "critical"


def test_score_is_bounded_and_explained():
    engine = RiskEngine(asset_criticality=5, recent_incidents=2, historical_alert_count=30)
    result = engine.score(
        severity="critical",
        confidence=1.0,
        signals=[{"key": "ti", "label": "Threat feed", "weight": 40, "detail": "", "source": "ti"}],
        repeat_count=9,
    )
    assert 0 <= result.score <= 100
    assert result.score == 100
    assert result.signals
    assert result.explanation
    assert result.band == "critical"


def test_low_confidence_reduces_base_score():
    high = RiskEngine().score(severity="high", confidence=1.0)
    low = RiskEngine().score(severity="high", confidence=0.2)
    assert low.score < high.score
    assert high.score < 60  # severity alone does not automatically mean high risk


def test_critical_asset_increases_score():
    normal = RiskEngine(asset_criticality=3).score(severity="high", confidence=0.8).score
    critical = RiskEngine(asset_criticality=5).score(severity="high", confidence=0.8).score
    assert critical > normal


def test_signals_are_sanitised_and_counted():
    result = RiskEngine().score(
        severity="medium",
        confidence=0.5,
        signals=[
            {"key": "a", "label": "A", "weight": 5, "detail": "", "source": "x"},
            {"key": "b", "label": "B", "weight": 0, "detail": "", "source": "x"},
            {"key": "c", "label": "C", "weight": 7, "detail": "", "source": "x"},
        ],
    )
    keys = [s["key"] for s in result.signals]
    assert "a" in keys and "c" in keys
    assert "b" not in keys


def test_severity_for_score_mapping():
    assert severity_for_score(0) == "info"
    assert severity_for_score(25) == "low"
    assert severity_for_score(45) == "medium"
    assert severity_for_score(65) == "high"
    assert severity_for_score(85) == "critical"
