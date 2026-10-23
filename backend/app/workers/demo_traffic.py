"""Synthetic lab traffic generator.

This exists to exercise the pipeline end to end without touching a real
network. Every event it emits is tagged ``demo: true`` in ``raw`` and uses
documentation address ranges (RFC 5737) or private ranges only.

Usage:
    python -m app.workers.demo_traffic --interval 10 --batch 4

It is disabled unless ``FIRESTORM_DEMO_TRAFFIC=true``.
"""

from __future__ import annotations

import argparse
import logging
import random
import time
from datetime import UTC, datetime

from app.core.config import settings
from app.core.database import SessionLocal
from app.schemas.telemetry import EventIn
from app.services.detection_service import DetectionService

logger = logging.getLogger("firestorm.demo_traffic")

BENIGN_DESTS = [("10.20.20.11", 5432), ("10.20.20.12", 443), ("10.20.20.20", 445), ("198.51.100.10", 443)]
DEMO_SOURCES = ["10.20.10.21", "10.20.10.22", "10.20.10.23", "10.20.20.12", "10.20.20.13"]


def benign_event(rng: random.Random) -> EventIn:
    dst_ip, dst_port = rng.choice(BENIGN_DESTS)
    return EventIn(
        source="zeek",
        sensor="zeek-lab",
        event_type="flow",
        severity="info",
        ts=datetime.now(UTC),
        src_ip=rng.choice(DEMO_SOURCES),
        dst_ip=dst_ip,
        dst_port=dst_port,
        protocol="tcp",
        bytes_out=rng.randint(2_000, 500_000),
        bytes_in=rng.randint(1_000, 800_000),
        raw={"demo": True, "generator": "demo_traffic"},
        external_id=f"demo-{time.time_ns()}",
    )


def suspicious_event(rng: random.Random) -> EventIn:
    kind = rng.choice(["dns", "auth", "ids", "malware"])
    now = datetime.now(UTC)
    if kind == "dns":
        return EventIn(
            source="zeek", sensor="zeek-lab", event_type="dns_query", severity="low", ts=now,
            src_ip=rng.choice(DEMO_SOURCES), dst_ip="10.20.40.10", dst_port=53,
            dns_query=f"{rng.token_hex(8)}.exfil.example-lab.test",
            raw={"demo": True, "generator": "demo_traffic"}, external_id=f"demo-{time.time_ns()}",
        )
    if kind == "auth":
        return EventIn(
            source="wazuh", sensor="wazuh-lab", event_type="auth_failure", severity="medium", ts=now,
            src_ip="198.51.100.23", dst_ip="10.20.20.12", dst_port=22, username=rng.choice(["admin", "svc", "root"]),
            raw={"demo": True, "generator": "demo_traffic"}, external_id=f"demo-{time.time_ns()}",
        )
    if kind == "ids":
        return EventIn(
            source="suricata", sensor="suricata-lab", event_type="ids_alert", severity="high", ts=now,
            src_ip="198.51.100.23", dst_ip="10.20.20.12", dst_port=443,
            signature="ET LAB Suspicious request pattern (demo rule)",
            raw={"demo": True, "generator": "demo_traffic"}, external_id=f"demo-{time.time_ns()}",
        )
    return EventIn(
        source="wazuh", sensor="wazuh-lab", event_type="malware_detected", severity="high", ts=now,
        src_ip=rng.choice(DEMO_SOURCES), hostname="ws-vikram-win",
        file_hash="275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f",
        file_name="lab_test_sample.bin", signature="EICAR-Test-File (laboratory test artefact)",
        raw={"demo": True, "generator": "demo_traffic"}, external_id=f"demo-{time.time_ns()}",
    )


def run(interval: float = 15.0, batch: int = 3) -> None:
    if not settings.demo_traffic:
        print("FIRESTORM_DEMO_TRAFFIC is false; refusing to emit synthetic events.")
        return
    rng = random.Random()
    print(f"Emitting {batch} synthetic events every {interval}s. All events are labelled demo data.")
    while True:
        db = SessionLocal()
        try:
            service = DetectionService(db)
            for _ in range(batch):
                payload = suspicious_event(rng) if rng.random() < 0.25 else benign_event(rng)
                service.ingest(payload, commit=False)
            db.commit()
        except Exception:
            db.rollback()
            logger.exception("demo traffic cycle failed")
        finally:
            db.close()
        time.sleep(interval)


def main() -> int:
    parser = argparse.ArgumentParser(description="Generate synthetic lab telemetry")
    parser.add_argument("--interval", type=float, default=15.0)
    parser.add_argument("--batch", type=int, default=3)
    args = parser.parse_args()
    run(interval=args.interval, batch=max(1, min(args.batch, 50)))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
