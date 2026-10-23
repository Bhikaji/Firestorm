"""Containment workflow, four-eyes approval, reversibility, and admission."""

from __future__ import annotations

import uuid

from app.core.database import SessionLocal
from app.models.asset import Asset
from app.schemas.asset import PostureReport
from app.services.device_posture import AdmissionService, compute_posture


def _create_asset(client, admin_headers, **overrides) -> dict:
    payload = {
        "hostname": f"host-{uuid.uuid4().hex[:8]}",
        "ip_address": f"10.99.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
        "mac_address": "aa:bb:cc:dd:ee:ff",
        "device_type": "workstation",
        "criticality": 3,
    }
    payload.update(overrides)
    response = client.post("/api/v1/assets", headers=admin_headers, json=payload)
    assert response.status_code == 201, response.text
    return response.json()


def test_asset_crud_and_validation(client, admin_headers, viewer_headers):
    asset = _create_asset(client, admin_headers)
    assert client.get(f"/api/v1/assets/{asset['id']}", headers=viewer_headers).status_code == 200

    bad_ip = client.post(
        "/api/v1/assets", headers=admin_headers, json={"hostname": "bad", "ip_address": "999.1.1.1"}
    )
    assert bad_ip.status_code == 422

    assert client.post("/api/v1/assets", headers=viewer_headers, json={"hostname": "x", "ip_address": "10.0.0.9"}).status_code == 403


def test_posture_scoring_and_admission_outcomes(client, admin_headers):
    asset = _create_asset(client, admin_headers)
    db = SessionLocal()
    try:
        row = db.get(Asset, asset["id"])
        report = PostureReport(
            edr_status="active", patch_level="current", firewall_enabled=True, disk_encrypted=True,
            malware_detections_24h=0,
        )
        score, checks = compute_posture(row, report)
        assert score == 85  # 15 points missing while the device is not enrolled
        assert checks["enrolled"] is False
    finally:
        db.close()

    decision = client.post(f"/api/v1/assets/{asset['id']}/admission", headers=admin_headers)
    assert decision.status_code == 200
    body = decision.json()
    assert body["outcome"] in {"restrict_remediation", "deny"}


def test_enrolled_compliant_device_is_allowed(client, admin_headers):
    asset = _create_asset(client, admin_headers)
    db = SessionLocal()
    try:
        row = db.get(Asset, asset["id"])
        row.enrolled = True
        row.trust_state = "trusted"
        db.commit()
    finally:
        db.close()

    response = client.post(
        f"/api/v1/assets/{asset['id']}/posture",
        headers=admin_headers,
        json={
            "edr_status": "active",
            "patch_level": "current",
            "firewall_enabled": True,
            "disk_encrypted": True,
            "malware_detections_24h": 0,
        },
    )
    assert response.status_code == 200
    assert response.json()["posture_score"] == 100

    decision = client.post(f"/api/v1/assets/{asset['id']}/admission", headers=admin_headers).json()
    assert decision["outcome"] == "allow"
    assert decision["trust_state"] == "trusted"


def test_admission_fails_closed_without_rules(client, admin_headers):
    asset = _create_asset(client, admin_headers)
    db = SessionLocal()
    try:
        # Disable all rules: the engine must default to restricted access.
        from sqlalchemy import update

        from app.models.policy import AdmissionRule

        AdmissionService(db).ensure_default_rules()
        db.execute(update(AdmissionRule).values(enabled=False))
        db.commit()
        row = db.get(Asset, asset["id"])
        decision = AdmissionService(db).evaluate(row, persist=False)
        assert decision["outcome"] == "restrict_remediation"
        assert "No admission rule matched" in decision["reason"]
    finally:
        db.close()


def test_action_requires_approval_and_four_eyes(client, admin_headers, responder_headers):
    asset = _create_asset(client, admin_headers)
    request = client.post(
        "/api/v1/actions",
        headers=responder_headers,
        json={
            "action_type": "quarantine_asset",
            "target": asset["mac_address"],
            "reason": "Suspected malware per detection R-0001",
            "asset_id": asset["id"],
        },
    )
    assert request.status_code == 201, request.text
    action = request.json()
    assert action["status"] == "pending_approval"
    assert action["mode"] == "simulated"

    execute_too_early = client.post(f"/api/v1/actions/{action['id']}/execute", headers=responder_headers)
    assert execute_too_early.status_code == 409

    approve = client.post(
        f"/api/v1/actions/{action['id']}/approve", headers=admin_headers, json={"note": "validated evidence"}
    )
    assert approve.status_code == 200
    assert approve.json()["status"] == "approved"

    execute = client.post(f"/api/v1/actions/{action['id']}/execute", headers=responder_headers)
    assert execute.status_code == 200
    executed = execute.json()
    assert executed["status"] == "succeeded"
    assert executed["mode"] == "simulated"
    assert "no production change" in executed["result"].lower() or "simulated" in executed["result"].lower()

    enforcement = client.get("/api/v1/enforcement", headers=admin_headers).json()
    assert any(item["target"] == asset["mac_address"] for item in enforcement)

    revert = client.post(
        f"/api/v1/actions/{action['id']}/revert", headers=responder_headers, json={"note": "false positive"}
    )
    assert revert.status_code == 200
    assert revert.json()["status"] == "reverted"


def test_requester_cannot_approve_own_action(client, admin_headers):
    request = client.post(
        "/api/v1/actions",
        headers=admin_headers,
        json={"action_type": "block_ip", "target": "203.0.113.201", "reason": "Test self-approval guard"},
    )
    action = request.json()
    approve = client.post(f"/api/v1/actions/{action['id']}/approve", headers=admin_headers, json={})
    assert approve.status_code == 403
    assert "four-eyes" in approve.json()["error"]["message"]


def test_allowlisted_target_is_protected(client, admin_headers, responder_headers):
    asset = _create_asset(client, admin_headers, hostname="core-db-01", criticality=5)
    policy = client.get("/api/v1/policies", headers=admin_headers).json()
    approval_policy = next(p for p in policy if p["key"] == "response.approval")
    config = approval_policy["config"]
    config["allowlist"] = ["core-db-01"]
    client.patch("/api/v1/policies/response.approval", headers=admin_headers, json={"config": config})

    response = client.post(
        "/api/v1/actions",
        headers=responder_headers,
        json={
            "action_type": "quarantine_asset",
            "target": asset["mac_address"],
            "reason": "allowlist protection test",
            "asset_id": asset["id"],
        },
    )
    assert response.status_code == 403


def test_emergency_release_requires_admin(client, responder_headers, admin_headers):
    denied = client.post(
        "/api/v1/actions/emergency-release",
        headers=responder_headers,
        json={"note": "release all containment immediately"},
    )
    assert denied.status_code == 403

    short_note = client.post(
        "/api/v1/actions/emergency-release", headers=admin_headers, json={"note": "short"}
    )
    assert short_note.status_code == 422

    ok = client.post(
        "/api/v1/actions/emergency-release",
        headers=admin_headers,
        json={"note": "Authorised recovery drill - releasing all containment"},
    )
    assert ok.status_code == 200


def test_evidence_collection_and_integrity(client, analyst_headers, ingest_headers):
    incident = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={
            "title": "Evidence workflow test",
            "summary": "Collecting synthetic evidence for the verification endpoint.",
            "severity": "medium",
        },
    )
    assert incident.status_code == 201
    incident_id = incident.json()["id"]

    evidence = client.post(
        f"/api/v1/incidents/{incident_id}/evidence",
        headers=analyst_headers,
        json={
            "kind": "analyst_note",
            "label": "Analyst observation",
            "content": "Synthetic note used by the automated test suite.",
        },
    )
    assert evidence.status_code == 201
    body = evidence.json()
    assert len(body["sha256"]) == 64
    assert body["custody"][0]["actor"]

    verified = client.get(f"/api/v1/evidence/{body['id']}/verify", headers=analyst_headers)
    assert verified.status_code == 200
    assert verified.json()["verified"] in {True, None}


def test_incident_state_machine_rejects_invalid_transitions(client, analyst_headers):
    created = client.post(
        "/api/v1/incidents",
        headers=analyst_headers,
        json={
            "title": "State machine test",
            "summary": "Validating allowed incident transitions with synthetic data.",
            "severity": "low",
        },
    ).json()
    invalid = client.patch(
        f"/api/v1/incidents/{created['id']}", headers=analyst_headers, json={"status": "closed"}
    )
    # new -> closed is allowed by the state machine (false alarm closure)
    assert invalid.status_code == 200
    reopen = client.patch(
        f"/api/v1/incidents/{created['id']}", headers=analyst_headers, json={"status": "triage"}
    )
    assert reopen.status_code == 409


def test_requester_cannot_waive_mandatory_approval(client, admin_headers):
    """A caller must not be able to opt out of approval for a destructive action."""
    response = client.post(
        "/api/v1/actions",
        headers=admin_headers,
        json={
            "action_type": "disable_account",
            "target": "contractor.temp@example.com",
            "reason": "Attempt to bypass the approval gate (negative test)",
            "require_approval": False,
        },
    )
    assert response.status_code == 201, response.text
    assert response.json()["status"] == "pending_approval"
