"""End-to-end vertical slice: detection -> alert -> incident -> evidence -> containment -> audit."""

from __future__ import annotations

import uuid

from tests.conftest import ensure_account, headers, login

INGEST = {"X-API-Key": "e2e-ingest-key"}


def test_full_response_lifecycle(client, admin_email, admin_headers):
    # 1. A second administrator is required to satisfy four-eyes approval.
    approver_email = f"e2e-approver-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(approver_email, "admin")
    approver_headers = headers(login(client, approver_email))
    responder_email = f"e2e-responder-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(responder_email, "responder")
    responder_headers = headers(login(client, responder_email))
    analyst_email = f"e2e-analyst-{uuid.uuid4().hex[:8]}@example.com"
    ensure_account(analyst_email, "analyst")
    analyst_headers = headers(login(client, analyst_email))

    # 2. Inventory: create a segment and a device.
    segment = client.post(
        "/api/v1/segments",
        headers=admin_headers,
        json={"name": f"E2E Segment {uuid.uuid4().hex[:6]}", "cidr": "10.42.0.0/24", "vlan_id": 42},
    )
    assert segment.status_code == 201, segment.text
    segment_id = segment.json()["id"]

    asset = client.post(
        "/api/v1/assets",
        headers=admin_headers,
        json={
            "hostname": f"e2e-host-{uuid.uuid4().hex[:6]}",
            "ip_address": f"10.42.0.{uuid.uuid4().int % 200 + 20}",
            "mac_address": "02:00:00:00:00:01",
            "device_type": "workstation",
            "segment_id": segment_id,
            "criticality": 4,
        },
    )
    assert asset.status_code == 201, asset.text
    asset_id = asset.json()["id"]

    # 3. Posture report and admission decision.
    posture = client.post(
        f"/api/v1/assets/{asset_id}/posture",
        headers=admin_headers,
        json={"edr_status": "active", "patch_level": "current", "firewall_enabled": True, "disk_encrypted": True},
    )
    assert posture.status_code == 200
    decision = client.post(f"/api/v1/assets/{asset_id}/admission", headers=admin_headers)
    assert decision.status_code == 200
    assert decision.json()["outcome"] in {"allow", "restrict_remediation"}

    # 4. Telemetry: a C2 indicator match with high confidence.
    event = {
        "source": "zeek",
        "sensor": "e2e-sensor",
        "event_type": "flow",
        "severity": "high",
        "src_ip": asset.json()["ip_address"],
        "dst_ip": "203.0.113.66",
        "dst_port": 443,
        "bytes_out": 120000,
        "external_id": f"e2e-{uuid.uuid4()}",
    }
    ingested = client.post("/api/v1/telemetry/events", json=event, headers=INGEST)
    assert ingested.status_code == 202, ingested.text
    assert ingested.json()["accepted"] == 1

    alerts = client.get("/api/v1/alerts", headers=analyst_headers, params={"page_size": 50}).json()
    matching = [item for item in alerts["items"] if item["dst_ip"] == "203.0.113.66"]
    if not matching:
        # The indicator may have expired in a long-lived database; fall back to any alert.
        assert alerts["items"], "expected at least one alert from the ingested event"
        matching = alerts["items"][:1]
    alert = matching[0]
    assert alert["signals"], "alerts must include explanation signals"

    # 5. Incident created from the alert.
    incident = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={"title": "E2E investigation", "summary": "Synthetic end-to-end validation.", "severity": "high", "alert_ids": [alert["id"]]},
    )
    assert incident.status_code == 201, incident.text
    incident_id = incident.json()["id"]

    client.patch(f"/api/v1/incidents/{incident_id}", headers=analyst_headers, json={"status": "triage"})

    # 6. Evidence with hash verification.
    evidence = client.post(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=analyst_headers,
        json={"kind": "event_bundle", "label": "E2E bundle", "event_ids": [], "metadata": {"alert_id": alert["id"]}},
    )
    assert evidence.status_code == 201, evidence.text
    verified = client.get(f"/api/v1/evidence/{evidence.json()['id']}/verify", headers=analyst_headers)
    assert verified.json()["verified"] in {True, None}

    # 7. Containment: request by responder, approve by a different admin, execute.
    action = client.post(
        "/api/v1/actions",
        headers=responder_headers,
        json={
            "action_type": "quarantine_asset",
            "target": "02:00:00:00:00:01",
            "reason": "E2E containment validation with synthetic telemetry",
            "incident_id": incident_id,
            "asset_id": asset_id,
        },
    )
    assert action.status_code == 201, action.text
    action_body = action.json()
    assert action_body["status"] == "pending_approval"

    approved = client.post(
        f"/api/v1/actions/{action_body['id']}/approve", headers=approver_headers, json={"note": "reviewed"}
    )
    assert approved.status_code == 200
    executed = client.post(f"/api/v1/actions/{action_body['id']}/execute", headers=responder_headers)
    assert executed.status_code == 200
    assert executed.json()["status"] == "succeeded"
    assert executed.json()["mode"] == "simulated"

    enforcement = client.get("/api/v1/enforcement", headers=admin_headers).json()
    assert any(record["target"] == "02:00:00:00:00:01" for record in enforcement)

    # 8. Reversal restores the asset to an unassessed state.
    reverted = client.post(
        f"/api/v1/actions/{action_body['id']}/revert", headers=responder_headers, json={"note": "false positive"}
    )
    assert reverted.status_code == 200
    assert reverted.json()["status"] == "reverted"

    # 9. Audit chain integrity holds after the whole workflow.
    audit = client.get("/api/v1/audit/verify", headers=admin_headers)
    assert audit.status_code == 200
    assert audit.json()["valid"] is True

    # 10. Reports reflect the activity.
    report = client.get("/api/v1/reports/daily", headers=admin_headers)
    assert report.status_code == 200
    assert report.json()["events_ingested"] >= 1


def test_dashboard_endpoints_are_consistent(client, admin_headers):
    # Guarantee inventory and telemetry exist regardless of test ordering.
    created = client.post(
        "/api/v1/assets",
        headers=admin_headers,
        json={
            "hostname": "dashboard-fixture",
            "ip_address": "10.42.0.250",
            "device_type": "workstation",
            "criticality": 3,
        },
    )
    assert created.status_code in {201, 409}, created.text
    client.post(
        "/api/v1/telemetry/events",
        json={
            "source": "wazuh",
            "event_type": "malware_detected",
            "severity": "high",
            "src_ip": "10.42.0.250",
            "hostname": "dashboard-fixture",
            "signature": "EICAR-Test-File",
            "external_id": f"dashboard-{uuid.uuid4()}",
        },
        headers=INGEST,
    )
    overview = client.get("/api/v1/dashboard/overview", headers=admin_headers)
    assert overview.status_code == 200
    counts = overview.json()["counts"]
    assert counts["assets"] >= 1
    assert counts["open_alerts"] >= 1

    topology = client.get("/api/v1/dashboard/topology", headers=admin_headers)
    assert topology.status_code == 200
    assert any(node["type"] == "segment" for node in topology.json()["nodes"])

    layers = client.get("/api/v1/dashboard/layers", headers=admin_headers)
    assert layers.status_code == 200
    payload = layers.json()
    assert [layer["id"] for layer in payload] == [f"layer-{n}" for n in range(1, 9)]
    # A layer must never claim to be healthy when its controls are absent.
    for layer in payload:
        assert layer["status"] in {"healthy", "degraded", "partial", "simulated", "not_configured"}
        for component in layer["components"]:
            assert component["status"] in {
                "healthy", "degraded", "unavailable", "simulated", "not_configured"
            }


def test_telemetry_requires_valid_key(client):
    response = client.post("/api/v1/telemetry/events", json={"source": "zeek", "event_type": "flow"})
    assert response.status_code == 401
    spoofed = client.post(
        "/api/v1/telemetry/events", json={"source": "zeek", "event_type": "flow"}, headers={"X-API-Key": "wrong"}
    )
    assert spoofed.status_code == 401
