"""Explainable 0-100 risk scoring.

Design constraints from the project brief:

* deterministic and auditable - no opaque model decides containment;
* the score always ships with the list of contributing signals;
* severity and confidence stay separate values;
* asset criticality and historical incident context modulate the score;
* the *policy* may raise the score but may never silently lower a critical
  detection below the containment threshold.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Any

from app.models.base import Severity

SEVERITY_WEIGHT: dict[str, int] = {
    Severity.INFO: 2,
    Severity.LOW: 6,
    Severity.MEDIUM: 12,
    Severity.HIGH: 20,
    Severity.CRITICAL: 28,
}

BANDS: list[tuple[int, int, str, str]] = [
    (0, 19, "informational", "Low risk - informational, no action expected."),
    (20, 39, "guarded", "Guarded - monitor; correlate if it repeats."),
    (40, 59, "medium", "Medium risk - triage within the current shift."),
    (60, 79, "high", "High risk - investigate promptly; containment may be justified."),
    (80, 100, "critical", "Critical - immediate response; require approval before destructive action."),
]


@dataclass
class RiskResult:
    score: int
    band: str
    band_label: str
    explanation: str
    signals: list[dict[str, Any]]

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "band": self.band,
            "band_label": self.band_label,
            "explanation": self.explanation,
            "signals": self.signals,
        }


def band_for(score: int) -> tuple[str, str, str]:
    for low, high, name, label in BANDS:
        if low <= score <= high:
            return name, label, f"{low}-{high}"
    return "critical", BANDS[-1][3], "80-100"


class RiskEngine:
    """Combines detection signals into a bounded, explained score."""

    def __init__(
        self,
        *,
        historical_alert_count: int = 0,
        asset_criticality: int = 3,
        asset_trust_state: str = "unknown",
        recent_incidents: int = 0,
        config: dict[str, Any] | None = None,
    ) -> None:
        self.historical_alert_count = historical_alert_count
        self.asset_criticality = max(1, min(5, asset_criticality))
        self.asset_trust_state = asset_trust_state
        self.recent_incidents = recent_incidents
        self.config = config or {}

    def score(
        self,
        *,
        severity: str,
        confidence: float,
        signals: Iterable[dict[str, Any]] = (),
        repeat_count: int = 0,
    ) -> RiskResult:
        base = SEVERITY_WEIGHT.get(severity, SEVERITY_WEIGHT[Severity.MEDIUM])
        base = int(round(base * max(0.2, min(1.0, confidence))))

        contributions: list[dict[str, Any]] = [
            {
                "key": "severity_confidence",
                "label": f"Base severity {severity} x confidence {confidence:.0%}",
                "weight": base,
                "detail": "Deterministic severity/confidence product",
                "source": "risk_engine",
            }
        ]
        total = base

        for sig in signals:
            weight = int(sig.get("weight", 0))
            if weight <= 0:
                continue
            contributions.append(dict(sig))
            total += weight

        # Asset criticality scales impact: business-critical hosts matter more.
        criticality_bonus = (self.asset_criticality - 3) * 5
        if criticality_bonus:
            contributions.append(
                {
                    "key": "asset_criticality",
                    "label": f"Asset criticality {self.asset_criticality}/5",
                    "weight": criticality_bonus,
                    "detail": "Impact scaling from inventory criticality",
                    "source": "inventory",
                }
            )
            total += criticality_bonus

        if self.asset_trust_state in {"compromised", "quarantined"}:
            contributions.append(
                {
                    "key": "asset_state",
                    "label": f"Asset already {self.asset_trust_state}",
                    "weight": 10,
                    "detail": "Existing containment/compromise state raises priority",
                    "source": "inventory",
                }
            )
            total += 10
        elif self.asset_trust_state == "unknown":
            contributions.append(
                {
                    "key": "untrusted_asset",
                    "label": "Asset is not yet assessed",
                    "weight": 5,
                    "detail": "Unassessed devices carry unknown residual risk",
                    "source": "inventory",
                }
            )
            total += 5

        if repeat_count >= 3:
            repeat_bonus = min(15, 5 * (repeat_count // 3))
            contributions.append(
                {
                    "key": "repetition",
                    "label": f"Repeated {repeat_count}x",
                    "weight": repeat_bonus,
                    "detail": "Repeat detections increase confidence that this is not a one-off",
                    "source": "risk_engine",
                }
            )
            total += repeat_bonus

        if self.recent_incidents:
            bonus = min(12, 6 * self.recent_incidents)
            contributions.append(
                {
                    "key": "historical_incidents",
                    "label": f"{self.recent_incidents} recent incident(s) on this asset",
                    "weight": bonus,
                    "detail": "Historical incident context",
                    "source": "incidents",
                }
            )
            total += bonus

        if self.historical_alert_count > 5:
            bonus = min(8, self.historical_alert_count // 3)
            contributions.append(
                {
                    "key": "historical_alerts",
                    "label": f"{self.historical_alert_count} historical alerts",
                    "weight": bonus,
                    "detail": "Asset has a history of alerts",
                    "source": "alerts",
                }
            )
            total += bonus

        score = max(0, min(100, total))
        band, label, _ = band_for(score)
        top = sorted(contributions, key=lambda c: c["weight"], reverse=True)[:4]
        explanation = "; ".join(f"{c['label']} (+{c['weight']})" for c in top)
        return RiskResult(score=score, band=band, band_label=label, explanation=explanation, signals=contributions)


def severity_for_score(score: int) -> str:
    if score >= 80:
        return Severity.CRITICAL
    if score >= 60:
        return Severity.HIGH
    if score >= 40:
        return Severity.MEDIUM
    if score >= 20:
        return Severity.LOW
    return Severity.INFO
