"""Deterministic demonstration dataset.

Everything created here is **simulated lab data**: synthetic hosts on
documentation-range addresses (RFC 5737 for IPv4) and clearly-labelled
indicators. The API flags responses with ``demo`` when demo data is enabled so
the dashboard can label it.

Credentials: the bootstrap administrator password comes from
``FIRESTORM_BOOTSTRAP_ADMIN_PASSWORD`` or is generated on first run and printed
once by ``scripts/bootstrap.py``. Nothing here contains a hard-coded password.
"""

from __future__ import annotations

import logging
import random
import secrets
from collections.abc import Iterable
from datetime import UTC, datetime, timedelta

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import hash_password
from app.models.alert import Alert
from app.models.asset import Asset, Segment
from app.models.base import IncidentStatus, Severity, TrustState
from app.models.incident import Evidence, Incident, IncidentTimelineEvent, ResponseAction
from app.models.policy import Policy, ThreatIndicator
from app.models.telemetry import Event
from app.models.user import User
from app.services.audit_service import AuditService
from app.services.device_posture import AdmissionService
from app.services.threat_intel import import_indicators

logger = logging.getLogger("firestorm.seed")

DEMO_SEGMENTS = [
    {"name": "HQ Corporate", "cidr": "10.20.10.0/24", "vlan_id": 110, "sensitivity": "standard",
     "description": "Employee workstations and laptops (lab range)."},
    {"name": "Servers", "cidr": "10.20.20.0/24", "vlan_id": 120, "sensitivity": "restricted",
     "description": "Production application and database servers."},
    {"name": "IoT / OT", "cidr": "10.20.30.0/24", "vlan_id": 130, "sensitivity": "elevated",
     "description": "Cameras, sensors and building systems."},
    {"name": "Management", "cidr": "10.20.40.0/24", "vlan_id": 140, "sensitivity": "management",
     "description": "Administrative plane - no user traffic permitted."},
    {"name": "Quarantine", "cidr": "10.20.90.0/24", "vlan_id": 900, "sensitivity": "restricted",
     "description": "Remediation network for isolated endpoints."},
]

DEMO_ASSETS = [
    # hostname, ip, mac, type, os, owner, dept, segment_index, criticality, trust, enrolled, edr, patch, posture
    ("fw-core-01", "10.20.40.10", "00:1b:44:11:3a:b7", "firewall", "pfSense 2.7", "Network Ops", "IT", 3, 5, TrustState.TRUSTED, True, "active", "current", 95),
    ("db-prod-01", "10.20.20.11", "3c:52:82:0a:11:01", "server", "Ubuntu 24.04", "Platform", "IT", 1, 5, TrustState.TRUSTED, True, "active", "current", 92),
    ("app-prod-01", "10.20.20.12", "3c:52:82:0a:11:02", "server", "Ubuntu 24.04", "Platform", "IT", 1, 4, TrustState.TRUSTED, True, "active", "current", 88),
    ("app-prod-02", "10.20.20.13", "3c:52:82:0a:11:03", "server", "Ubuntu 24.04", "Platform", "IT", 1, 4, TrustState.NONCOMPLIANT, True, "degraded", "behind", 55),
    ("fileserver-01", "10.20.20.20", "3c:52:82:0a:11:20", "server", "Windows Server 2022", "Platform", "IT", 1, 4, TrustState.TRUSTED, True, "active", "current", 86),
    ("ws-anna-mac", "10.20.10.21", "a4:83:e7:2c:9b:10", "laptop", "macOS 15.1", "Anna Rao", "Finance", 0, 3, TrustState.TRUSTED, True, "active", "current", 90),
    ("ws-vikram-win", "10.20.10.22", "a4:83:e7:2c:9b:11", "workstation", "Windows 11", "Vikram Shah", "Engineering", 0, 3, TrustState.TRUSTED, True, "active", "current", 84),
    ("ws-meera-linux", "10.20.10.23", "a4:83:e7:2c:9b:12", "workstation", "Ubuntu 22.04", "Meera Iyer", "Engineering", 0, 2, TrustState.NONCOMPLIANT, True, "active", "critical_pending", 48),
    ("ws-rahul-win", "10.20.10.24", "a4:83:e7:2c:9b:13", "workstation", "Windows 10", "Rahul Nair", "Sales", 0, 2, TrustState.QUARANTINED, True, "inactive", "behind", 32),
    ("iot-camera-07", "10.20.30.31", "9c:8e:99:44:07:31", "camera", "Embedded Linux", "Facilities", "Facilities", 2, 2, TrustState.UNKNOWN, False, "unknown", "unknown", 0),
    ("iot-hvac-02", "10.20.30.32", "9c:8e:99:44:07:32", "sensor", "Embedded RTOS", "Facilities", "Facilities", 2, 3, TrustState.UNKNOWN, False, "unknown", "unknown", 0),
    ("unknown-laptop", "10.20.10.99", "b8:27:eb:aa:99:01", "laptop", "Unknown", None, None, 0, 1, TrustState.UNKNOWN, False, "unknown", "unknown", 0),
]

DEMO_INDICATORS = [
    {"type": "ip", "value": "203.0.113.66", "category": "c2", "confidence": 90, "severity": "critical",
     "source": "lab-feed", "description": "Synthetic C2 address used for detection testing (documentation range)."},
    {"type": "domain", "value": "update-check.example-malicious.test", "category": "malware_download",
     "confidence": 85, "severity": "high", "source": "lab-feed",
     "description": "Synthetic malware distribution domain."},
    {"type": "domain", "value": "beacon.example-c2.test", "category": "c2", "confidence": 92, "severity": "critical",
     "source": "lab-feed", "description": "Synthetic beaconing domain."},
    {"type": "sha256", "value": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
     "category": "malware", "confidence": 88, "severity": "high", "source": "lab-feed",
     "description": "EICAR anti-malware test file hash - safe, non-malicious test artefact."},
    {"type": "ip", "value": "198.51.100.23", "category": "scanner", "confidence": 60, "severity": "medium",
     "source": "lab-feed", "description": "Synthetic scanning source (documentation range)."},
]

DEMO_USERS = [
    # email, name, role
    ("analyst@firestorm.example.com", "Priya Analyst", "analyst"),
    ("responder@firestorm.example.com", "Arjun Responder", "responder"),
    ("viewer@firestorm.example.com", "Sana Viewer", "viewer"),
    ("approver@firestorm.example.com", "Dev Approver", "admin"),
]


def _now() -> datetime:
    return datetime.now(UTC)


def _exists(db: Session, model) -> bool:
    return db.execute(select(func.count(model.id))).scalar_one() > 0


def seed_threat_intel(db: Session) -> int:
    if _exists(db, ThreatIndicator):
        return 0
    return import_indicators(db, DEMO_INDICATORS, source="lab-feed", ttl_days=180)


def seed_segments_and_assets(db: Session, rng: random.Random) -> tuple[list[Segment], list[Asset]]:
    if _exists(db, Asset):
        return list(db.execute(select(Segment)).scalars().all()), list(db.execute(select(Asset)).scalars().all())

    segments = [Segment(**segment) for segment in DEMO_SEGMENTS]
    db.add_all(segments)
    db.flush()

    assets: list[Asset] = []
    for row in DEMO_ASSETS:
        (hostname, ip, mac, device_type, os_name, owner, dept, seg_idx, criticality,
         trust, enrolled, edr, patch, posture) = row
        asset = Asset(
            hostname=hostname,
            ip_address=ip,
            mac_address=mac,
            device_type=device_type,
            os_name=os_name,
            os_version="",
            owner=owner,
            department=dept,
            segment_id=segments[seg_idx].id,
            criticality=criticality,
            trust_state=trust,
            enrolled=enrolled,
            edr_status=edr,
            patch_level=patch,
            firewall_enabled=True if enrolled else None,
            disk_encrypted=True if enrolled else None,
            posture_score=float(posture),
            last_posture_at=_now() - timedelta(minutes=rng.randint(2, 120)) if enrolled else None,
            last_seen_at=_now() - timedelta(minutes=rng.randint(0, 45)),
            quarantine_reason="Malware detected by endpoint agent" if trust == TrustState.QUARANTINED else None,
            quarantined_at=_now() - timedelta(hours=3) if trust == TrustState.QUARANTINED else None,
            tags={"demo": True, "source": "seed"},
        )
        db.add(asset)
        assets.append(asset)
    db.flush()
    return segments, assets


def seed_users(db: Session) -> list[User]:
    users: list[User] = []
    for email, name, role in DEMO_USERS:
        existing = db.execute(select(User).where(User.email == email)).scalars().first()
        if existing:
            users.append(existing)
            continue
        password = settings.demo_password or f"Demo-{secrets.token_urlsafe(12)}"
        user = User(
            email=email,
            full_name=name,
            role=role,
            password_hash=hash_password(password),
            must_change_password=True,
        )
        db.add(user)
        users.append(user)
        print(f"[seed] demo user {email} created with one-time password: {password}")
    db.flush()
    return users


def ensure_admin(db: Session) -> User:
    email = settings.bootstrap_admin_email.lower()
    existing = db.execute(select(User).where(User.email == email)).scalars().first()
    if existing:
        return existing
    password = settings.bootstrap_admin_password or f"Fs-{secrets.token_urlsafe(18)}"
    user = User(
        email=email,
        full_name=settings.bootstrap_admin_name,
        role="admin",
        password_hash=hash_password(password),
        must_change_password=not bool(settings.bootstrap_admin_password),
    )
    db.add(user)
    db.flush()
    if not settings.bootstrap_admin_password:
        print("=" * 78)
        print(" FIRESTORM bootstrap administrator created")
        print(f"   email:    {email}")
        print(f"   password: {password}")
        print("   This password is shown once. Sign in and change it immediately.")
        print("=" * 78)
    return user


def _emit(db: Session, detector, events: Iterable[dict]) -> int:
    from app.schemas.telemetry import EventIn

    count = 0
    for payload in events:
        try:
            event, alerts = detector.ingest(EventIn(**payload), commit=False)
        except Exception:  # noqa: BLE001 - synthetic seed data must not abort seeding
            logger.warning("seed event rejected")
            continue
        if event:
            count += 1
    return count


def seed_demo_activity(db: Session, assets: list[Asset], rng: random.Random) -> dict[str, int]:
    """Generate synthetic telemetry that exercises the detection pipeline."""
    from app.services.detection_service import DetectionService

    if _exists(db, Event):
        return {"events": 0, "alerts": 0}

    detector = DetectionService(db)
    now = _now()
    by_host = {a.hostname: a for a in assets}
    events: list[dict] = []

    # 1. Benign baseline traffic
    for i in range(120):
        asset = assets[i % 9]
        ts = now - timedelta(minutes=rng.randint(1, 60 * 12))
        events.append(
            {
                "source": "zeek",
                "sensor": "zeek-hq-01",
                "event_type": "flow",
                "severity": "info",
                "ts": ts,
                "src_ip": asset.ip_address,
                "dst_ip": rng.choice(["10.20.20.12", "10.20.20.11", "10.20.20.20", "198.51.100.10"]),
                "dst_port": rng.choice([443, 80, 53, 445, 22]),
                "protocol": "tcp",
                "bytes_out": rng.randint(2_000, 400_000),
                "bytes_in": rng.randint(2_000, 900_000),
                "hostname": asset.hostname,
                "external_id": f"zeek-baseline-{i}",
            }
        )

    # 2. Malware detection on the quarantined workstation (EICAR hash)
    ws_rahul = by_host["ws-rahul-win"]
    events.append(
        {
            "source": "wazuh",
            "sensor": "wazuh-manager",
            "event_type": "malware_detected",
            "severity": "critical",
            "ts": now - timedelta(hours=3, minutes=12),
            "src_ip": ws_rahul.ip_address,
            "hostname": ws_rahul.hostname,
            "username": "rahul.nair",
            "file_hash": "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
            "file_name": "invoice_2026.exe",
            "signature": "EICAR-Test-File (laboratory test artefact)",
            "external_id": "wazuh-malware-eicar-1",
        }
    )

    # 3. C2 beaconing to a lab indicator
    ws_meera = by_host["ws-meera-linux"]
    for i in range(12):
        events.append(
            {
                "source": "zeek",
                "sensor": "zeek-hq-01",
                "event_type": "flow",
                "severity": "medium",
                "ts": now - timedelta(hours=2, minutes=i * 5),
                "src_ip": ws_meera.ip_address,
                "dst_ip": "203.0.113.66",
                "dst_port": 8443,
                "protocol": "tcp",
                "bytes_out": 4_000,
                "bytes_in": 2_500,
                "hostname": ws_meera.hostname,
                "external_id": f"zeek-beacon-{i}",
            }
        )

    # 4. Authentication brute force against the app server
    for i in range(14):
        events.append(
            {
                "source": "wazuh",
                "sensor": "wazuh-manager",
                "event_type": "auth_failure",
                "severity": "medium",
                "ts": now - timedelta(hours=1, minutes=60 - i * 3),
                "src_ip": "198.51.100.23",
                "dst_ip": "10.20.20.12",
                "dst_port": 22,
                "username": f"svc{i % 3}",
                "hostname": "app-prod-01",
                "external_id": f"wazuh-authfail-{i}",
            }
        )

    # 5. Port scan from an unregistered device
    for port in [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 445, 993, 1433, 3306, 3389, 5432, 8080, 8443, 9200]:
        events.append(
            {
                "source": "suricata",
                "sensor": "suricata-edge",
                "event_type": "network_connection",
                "severity": "low",
                "ts": now - timedelta(minutes=90),
                "src_ip": "10.20.10.99",
                "dst_ip": "10.20.20.20",
                "dst_port": port,
                "protocol": "tcp",
                "signature": "Potential port sweep",
                "external_id": f"suricata-scan-{port}",
            }
        )

    # 6. Threat-intel matched DNS lookup
    events.append(
        {
            "source": "zeek",
            "sensor": "zeek-dns",
            "event_type": "dns_query",
            "severity": "medium",
            "ts": now - timedelta(minutes=45),
            "src_ip": ws_meera.ip_address,
            "dst_ip": "10.20.40.10",
            "dns_query": "update-check.example-malicious.test",
            "hostname": ws_meera.hostname,
            "external_id": "zeek-dns-ti-1",
        }
    )

    # 7. IDS exploit attempt signature
    events.append(
        {
            "source": "suricata",
            "sensor": "suricata-edge",
            "event_type": "ids_alert",
            "severity": "high",
            "ts": now - timedelta(minutes=25),
            "src_ip": "198.51.100.23",
            "dst_ip": "10.20.20.13",
            "dst_port": 443,
            "signature": "ET WEB_SPECIFIC_APPS Possible Apache Struts RCE (lab rule)",
            "external_id": "suricata-ids-1",
        }
    )

    # 8. Phishing email delivered to finance
    events.append(
        {
            "source": "firestorm",
            "sensor": "mail-gateway",
            "event_type": "email_received",
            "severity": "medium",
            "ts": now - timedelta(minutes=15),
            "src_ip": "198.51.100.77",
            "hostname": "ws-anna-mac",
            "raw": {
                "subject": "Urgent: Invoice payment required",
                "from": "billing@example-invoice.test",
                "to": "anna.rao@example.test",
                "spf": "fail",
                "dkim": "none",
                "dmarc": "fail",
                "urls": ["https://login.example-invoice.test/verify"],
                "message_id": "<demo-phish-001@example-invoice.test>",
            },
            "external_id": "mail-phish-1",
        }
    )

    # 9. Unknown device reaching an administrative service
    events.append(
        {
            "source": "firewall",
            "sensor": "fw-core-01",
            "event_type": "admission_denied",
            "severity": "medium",
            "ts": now - timedelta(minutes=8),
            "src_ip": "10.20.10.99",
            "dst_ip": "10.20.20.11",
            "dst_port": 5432,
            "action": "deny",
            "external_id": "fw-admission-deny-1",
        }
    )

    # 10. Large egress from a server (exfiltration candidates)
    for i in range(5):
        events.append(
            {
                "source": "zeek",
                "sensor": "zeek-hq-01",
                "event_type": "flow",
                "severity": "medium",
                "ts": now - timedelta(minutes=40 + i),
                "src_ip": "10.20.20.13",
                "dst_ip": "203.0.113.200",
                "dst_port": 443,
                "protocol": "tcp",
                "bytes_out": 18_000_000,
                "bytes_in": 120_000,
                "hostname": "app-prod-02",
                "external_id": f"zeek-egress-{i}",
            }
        )

    count = _emit(db, detector, events)
    alerts = int(db.execute(select(func.count(Alert.id))).scalar_one())
    return {"events": count, "alerts": alerts}


def seed_incident_history(db: Session, admin: User) -> int:
    if _exists(db, Incident):
        return 0
    assets = db.execute(select(Asset)).scalars().all()
    quarantined = next((a for a in assets if a.trust_state == TrustState.QUARANTINED), None)
    incident = Incident(
        reference=f"INC-{_now():%Y%m%d}-DEMO01",
        title="Endpoint malware on finance workstation (demonstration)",
        summary=(
            "Demonstration incident built from synthetic telemetry. The endpoint agent reported a laboratory "
            "test artefact; the endpoint was quarantined pending validation."
        ),
        severity=Severity.CRITICAL,
        status=IncidentStatus.CONTAINED,
        risk_score=91,
        owner_id=admin.id,
        detected_at=_now() - timedelta(hours=3, minutes=20),
        contained_at=_now() - timedelta(hours=3, minutes=2),
        observed_facts=[
            {"fact": "Malware signature reported", "detail": "EICAR laboratory test artefact", "source": "wazuh"},
            {"fact": "Host identified", "detail": quarantined.hostname if quarantined else "ws-rahul-win"},
            {"fact": "Containment applied", "detail": "VLAN moved to quarantine (simulated adapter)"},
        ],
        hypotheses=[
            {"hypothesis": "User executed an email attachment", "confidence": 0.55, "status": "unverified"},
            {"hypothesis": "Lateral movement to file server", "confidence": 0.15, "status": "unlikely"},
        ],
        affected_asset_ids=[quarantined.id] if quarantined else [],
        affected_accounts=["rahul.nair"],
        mitre_tactics=["Execution", "Defense Evasion"],
        post_incident_review=(
            "Demo review: detection and containment worked as designed on synthetic data. "
            "Production review should validate email gateway logs and user interview."
        ),
    )
    db.add(incident)
    db.flush()

    timeline = [
        (incident.detected_at, "detection", "detection-engine", "Malware detection alert created (R-0001)"),
        (incident.detected_at + timedelta(minutes=2), "status", "analyst@firestorm.example.com", "Incident triaged; owner assigned"),
        (incident.detected_at + timedelta(minutes=5), "evidence", "analyst@firestorm.example.com", "Endpoint event bundle collected and hashed"),
        (incident.detected_at + timedelta(minutes=12), "action", "approver@firestorm.example.com", "Quarantine action approved"),
        (incident.detected_at + timedelta(minutes=15), "action", "responder@firestorm.example.com", "Quarantine executed on simulated NAC adapter"),
        (incident.detected_at + timedelta(minutes=18), "status", "analyst@firestorm.example.com", "Incident marked contained"),
    ]
    for ts, kind, actor, message in timeline:
        db.add(
            IncidentTimelineEvent(
                incident_id=incident.id, ts=ts, kind=kind, actor=actor, message=message, payload={"demo": True}
            )
        )

    action = ResponseAction(
        incident_id=incident.id,
        action_type="quarantine_asset",
        target=quarantined.mac_address if quarantined and quarantined.mac_address else "00:00:00:00:00:00",
        asset_id=quarantined.id if quarantined else None,
        status="succeeded",
        reason="Contain endpoint with a reported malware detection pending validation.",
        requested_by=admin.id,
        approved_by=admin.id,
        approved_at=incident.detected_at + timedelta(minutes=12),
        executed_at=incident.detected_at + timedelta(minutes=15),
        integration="UniFi NAC (simulated)",
        mode="simulated",
        result="Simulated nac for device; no production change was made.",
        confidence=0.9,
        reversible=True,
    )
    db.add(action)

    evidence = Evidence(
        incident_id=incident.id,
        kind="event_bundle",
        label="Endpoint telemetry bundle (demo)",
        sha256="0" * 64,
        size_bytes=1024,
        collected_by="analyst@firestorm.example.com",
        source="firestorm",
        custody=[
            {"ts": (_now() - timedelta(hours=3)).isoformat(), "actor": "analyst@firestorm.example.com",
             "action": "collected", "sha256": "0" * 64}
        ],
        metadata_json={"demo": True, "note": "Synthetic evidence record; no real endpoint data."},
    )
    db.add(evidence)
    db.flush()
    return 1


def ensure_default_configuration(db: Session) -> None:
    """Insert default policies and admission rules when the database is empty.

    Safe to call on every start: it only inserts missing keys.
    """
    from app.api.policies import DEFAULT_POLICIES

    AdmissionService(db).ensure_default_rules()
    for item in DEFAULT_POLICIES:
        if not db.execute(select(Policy).where(Policy.key == item["key"])).scalars().first():
            db.add(Policy(**item))
    db.commit()


def seed_all(db: Session, *, with_users: bool = True) -> dict[str, int]:
    """Idempotent seeding entry point used by scripts/bootstrap.py and tests."""
    rng = random.Random(1337)
    audit = AuditService(db)
    admin = ensure_admin(db)
    counts = {"segments": 0, "assets": 0, "users": 0, "indicators": 0, "events": 0, "alerts": 0, "incidents": 0}

    ensure_default_configuration(db)

    if settings.demo_data:
        counts["indicators"] = seed_threat_intel(db)
        if with_users:
            before = db.execute(select(func.count(User.id))).scalar_one()
            seed_users(db)
            counts["users"] = int(db.execute(select(func.count(User.id))).scalar_one()) - int(before)
        segments, assets = seed_segments_and_assets(db, rng)
        counts["segments"] = len(segments)
        counts["assets"] = len(assets)
        db.flush()
        activity = seed_demo_activity(db, assets, rng)
        counts["events"] = activity["events"]
        counts["alerts"] = activity["alerts"]
        counts["incidents"] = seed_incident_history(db, admin)
    db.flush()
    audit.record(
        action="system.seeded",
        actor_email="bootstrap",
        actor_role="system",
        object_type="system",
        detail={"demo_data": settings.demo_data, **counts},
    )
    db.commit()
    return counts
