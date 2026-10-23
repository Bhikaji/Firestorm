"""Deterministic detection rules tested with synthetic telemetry only."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from app.models.telemetry import Event
from app.services.detection_rules import EventContext, evaluate, rules_catalog
from app.services.threat_intel import IndicatorMatch


def make_event(**overrides) -> Event:
    data = {
        "id": "evt-1",
        "ts": datetime.now(UTC),
        "received_at": datetime.now(UTC),
        "source": "zeek",
        "event_type": "flow",
        "severity": "info",
        "src_ip": "10.0.0.5",
        "dst_ip": "10.0.0.6",
        "dst_port": 443,
        "bytes_out": 1000,
        "bytes_in": 1000,
        "packets": 10,
        "risk_score": 0,
        "processed": False,
        "fingerprint": "fp",
        "raw": {},
        "bytes_in_": 0,
    }
    data.update(overrides)
    event = Event()
    for key, value in data.items():
        if hasattr(event, key):
            setattr(event, key, value)
    return event


def ctx(event: Event, related: list[Event] | None = None, **kwargs) -> EventContext:
    return EventContext(event=event, related=related or [], **kwargs)


def test_rule_catalog_is_complete():
    catalog = rules_catalog()
    assert len(catalog) >= 13
    assert all(item["rule_id"].startswith("R-") for item in catalog)


def test_benign_flow_produces_no_detection():
    event = make_event()
    assert evaluate(ctx(event)) == []


def test_malware_detection_escalates_on_critical_asset():
    event = make_event(
        event_type="malware_detected",
        source="wazuh",
        severity="critical",
        signature="EICAR-Test-File",
        hostname="ws-01",
    )
    detections = evaluate(ctx(event, asset_criticality=5))
    assert len(detections) == 1
    detection = detections[0]
    assert detection.rule_id == "R-0001"
    assert detection.severity == "critical"
    assert detection.ttps == ["T1204", "T1105"]
    assert "quarantine_asset" in detection.recommended_actions


def test_port_scan_requires_breadth():
    related = [make_event(id=f"e{i}", dst_port=p) for i, p in enumerate([22, 80, 443, 8080])]
    assert evaluate(ctx(make_event(dst_port=8080), related)) == []

    broad = [make_event(id=f"e{i}", dst_port=1000 + i) for i in range(20)]
    detections = evaluate(ctx(make_event(dst_port=1019), broad))
    assert any(d.rule_id == "R-0003" for d in detections)


def test_bruteforce_rule_threshold():
    few = [make_event(id=f"f{i}", event_type="auth_failure", username="svc") for i in range(3)]
    assert not any(d.rule_id == "R-0004" for d in evaluate(ctx(make_event(event_type="auth_failure"), few)))

    many = [make_event(id=f"f{i}", event_type="auth_failure", username=f"svc{i % 4}") for i in range(12)]
    detections = evaluate(ctx(make_event(event_type="auth_failure"), many))
    assert any(d.rule_id == "R-0004" for d in detections)


def test_c2_beaconing_requires_regular_interval():
    base = datetime.now(UTC)
    regular = [
        make_event(id=f"b{i}", ts=base - timedelta(minutes=5 * i), dst_ip="203.0.113.9", event_type="flow")
        for i in range(10)
    ]
    detections = evaluate(ctx(make_event(dst_ip="203.0.113.9"), regular))
    assert any(d.rule_id == "R-0008" for d in detections)

    irregular_times = [0, 1, 14, 15, 40, 41, 90, 91, 200, 201]
    irregular = [
        make_event(id=f"j{i}", ts=base - timedelta(minutes=m), dst_ip="203.0.113.10")
        for i, m in enumerate(irregular_times)
    ]
    assert not any(d.rule_id == "R-0008" for d in evaluate(ctx(make_event(dst_ip="203.0.113.10"), irregular)))


def test_dns_tunneling_entropy_signal():
    base = datetime.now(UTC)
    queries = [
        make_event(
            id=f"d{i}",
            event_type="dns_query",
            dns_query=f"{'a1b2c3d4e5f6g7h8i9j0' * 2}{i}.tunnel.example.test",
            ts=base - timedelta(seconds=i),
        )
        for i in range(30)
    ]
    detections = evaluate(ctx(queries[0], queries))
    assert any(d.rule_id == "R-0005" for d in detections)


def test_threat_intel_match_scores_high():
    match = IndicatorMatch(
        indicator="203.0.113.66",
        indicator_type="ip",
        category="c2",
        confidence=95,
        severity="critical",
        source="test-feed",
        description="lab",
    )
    event = make_event(dst_ip="203.0.113.66")
    detections = evaluate(ctx(event, threat_match=match))
    detection = next(d for d in detections if d.rule_id == "R-0010")
    assert detection.severity == "critical"
    assert detection.confidence >= 0.9
    assert "203.0.113.66" in detection.title


def test_phishing_requires_multiple_auth_failures_or_links():
    weak = make_event(
        event_type="email_received",
        source="firestorm",
        raw={"subject": "hello", "spf": "pass", "dkim": "pass", "dmarc": "pass", "urls": []},
    )
    assert not any(d.rule_id == "R-0012" for d in evaluate(ctx(weak)))

    strong = make_event(
        event_type="email_received",
        source="firestorm",
        raw={
            "subject": "Invoice",
            "from": "billing@example.test",
            "spf": "fail",
            "dkim": "fail",
            "dmarc": "fail",
            "urls": ["https://example.test/verify"],
            "message_id": "<x@y>",
        },
    )
    detections = evaluate(ctx(strong))
    detection = next(d for d in detections if d.rule_id == "R-0012")
    assert detection.severity == "high"


def test_detection_fingerprint_is_stable():
    event = make_event(event_type="malware_detected", source="wazuh", signature="X", hostname="h1")
    first = evaluate(ctx(event))[0].fingerprint
    second = evaluate(ctx(event))[0].fingerprint
    assert first == second


@pytest.mark.parametrize("rule_id", ["R-0001", "R-0003", "R-0004", "R-0005", "R-0006", "R-0007", "R-0008"])
def test_rules_never_raise_on_minimal_event(rule_id):
    minimal = make_event(src_ip=None, dst_ip=None, dst_port=None)
    evaluate(ctx(minimal), rule_ids=[rule_id])
