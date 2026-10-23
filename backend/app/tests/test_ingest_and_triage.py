"""Ingestion pipeline, deduplication, alerts and incident workflow."""

from __future__ import annotations

import uuid

from app.tests.conftest import auth_headers, login


def event_payload(ip: str, **overrides) -> dict:
    payload = {
        "source": "wazuh",
        "sensor": "test-sensor",
        "event_type": "malware_detected",
        "severity": "critical",
        "src_ip": ip,
        "hostname": "test-host",
        "signature": "EICAR-Test-File",
        "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
    }
    payload.update(overrides)
    return payload


def test_ingest_requires_api_key(client):
    response = client.post("/api/v1/telemetry/events", json=event_payload("198.51.100.11"))
    assert response.status_code == 401


def test_ingest_rejects_bad_api_key(client):
    response = client.post(
        "/api/v1/telemetry/events", json=event_payload("198.51.100.12"), headers={"X-API-Key": "nope"}
    )
    assert response.status_code == 401


def test_ingest_creates_alert_and_incident(client, ingest_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    response = client.post("/api/v1/telemetry/events", json=event_payload(ip), headers=ingest_headers)
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 1
    assert body["alerts_created"] >= 1

    db_login = login(client, "analyst@example.com")
    headers = auth_headers(db_login["access_token"])
    alerts = client.get("/api/v1/alerts", headers=headers, params={"q": "test-host"}).json()
    assert alerts["total"] >= 1
    alert = alerts["items"][0]
    assert alert["rule_id"] == "R-0001"
    assert alert["risk_score"] >= 60
    assert alert["signals"]


def test_duplicate_event_is_idempotent(client, ingest_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    payload = event_payload(ip, external_id=f"dup-{uuid.uuid4()}")
    first = client.post("/api/v1/telemetry/events", json=payload, headers=ingest_headers)
    second = client.post("/api/v1/telemetry/events", json=payload, headers=ingest_headers)
    assert first.json()["accepted"] == 1
    assert second.json()["duplicates"] == 1


def test_repeated_events_deduplicate_into_one_alert(client, ingest_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    for i in range(3):
        client.post(
            "/api/v1/telemetry/events",
            json=event_payload(ip, external_id=f"dedupe-{ip}-{i}"),
            headers=ingest_headers,
        )
    headers = auth_headers(login(client, "analyst@example.com")["access_token"])
    alerts = client.get("/api/v1/alerts", headers=headers, params={"q": "test-host"}).json()
    matching = [a for a in alerts["items"] if a["rule_id"] == "R-0001"]
    assert len(matching) == 1
    assert matching[0]["occurrence_count"] >= 2


def test_batch_ingest_reports_counts(client, ingest_headers):
    payload = {
        "events": [
            event_payload("198.51.100.31", external_id="batch-1"),
            event_payload("198.51.100.31", external_id="batch-1"),
            event_payload("198.51.100.32", external_id="batch-2"),
        ]
    }
    response = client.post("/api/v1/telemetry/events/batch", json=payload, headers=ingest_headers)
    assert response.status_code == 202
    body = response.json()
    assert body["accepted"] == 2
    assert body["duplicates"] == 1


def test_oversized_batch_is_rejected(client, ingest_headers):
    payload = {"events": [event_payload("198.51.100.40", external_id=f"big-{i}") for i in range(501)]}
    response = client.post("/api/v1/telemetry/events/batch", json=payload, headers=ingest_headers)
    assert response.status_code == 422


def test_invalid_ip_and_port_are_rejected(client, ingest_headers):
    bad_ip = client.post(
        "/api/v1/telemetry/events", json=event_payload("not-an-ip"), headers=ingest_headers
    )
    assert bad_ip.status_code == 422
    bad_port = client.post(
        "/api/v1/telemetry/events",
        json=event_payload("198.51.100.50", dst_port=99999),
        headers=ingest_headers,
    )
    assert bad_port.status_code == 422


def test_alert_triage_and_suppression(client, ingest_headers, analyst_headers, admin_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    client.post(
        "/api/v1/telemetry/events",
        json=event_payload(ip, external_id=f"triage-{ip}"),
        headers=ingest_headers,
    )
    alerts = client.get("/api/v1/alerts", headers=analyst_headers, params={"q": "test-host"}).json()
    alert = alerts["items"][0]

    triaged = client.patch(
        f"/api/v1/alerts/{alert['id']}",
        headers=analyst_headers,
        json={"status": "acknowledged", "note": "Investigating endpoint", "create_incident": True},
    )
    assert triaged.status_code == 200
    assert triaged.json()["status"] == "acknowledged"
    assert triaged.json()["incident_id"]

    suppression = client.post(
        "/api/v1/alerts/suppressions",
        headers=admin_headers,
        json={"rule_id": "R-0001", "reason": "Duplicate of change ticket CHG-1234", "duration_minutes": 60},
    )
    assert suppression.status_code == 201
    assert suppression.json()["active"] is True


def test_closed_alert_cannot_be_reopened(client, ingest_headers, analyst_headers):
    ip = f"198.51.100.{uuid.uuid4().int % 200 + 20}"
    client.post(
        "/api/v1/telemetry/events",
        json=event_payload(ip, external_id=f"close-{ip}"),
        headers=ingest_headers,
    )
    alert = client.get("/api/v1/alerts", headers=analyst_headers, params={"q": "test-host"}).json()["items"][0]
    client.patch(f"/api/v1/alerts/{alert['id']}", headers=analyst_headers, json={"status": "closed"})
    reopened = client.patch(f"/api/v1/alerts/{alert['id']}", headers=analyst_headers, json={"status": "open"})
    assert reopened.status_code == 409


def test_event_stream_and_filtering(client, ingest_headers, analyst_headers):
    client.post(
        "/api/v1/telemetry/events",
        json=event_payload("198.51.100.60", external_id=f"stream-{uuid.uuid4()}"),
        headers=ingest_headers,
    )
    response = client.get(
        "/api/v1/telemetry/events", headers=analyst_headers, params={"source": "wazuh", "page_size": 5}
    )
    assert response.status_code == 200
    assert response.json()["page_size"] == 5
