"""Coarse ingestion throughput and pagination checks.

These are smoke-level benchmarks, not a substitute for a load test against a
production-sized PostgreSQL deployment.
"""

from __future__ import annotations

import time
import uuid

INGEST = {"X-API-Key": "e2e-ingest-key"}


def test_batch_ingest_throughput(client):
    batch = {
        "events": [
            {
                "source": "zeek",
                "sensor": "perf-sensor",
                "event_type": "flow",
                "severity": "info",
                "src_ip": f"10.60.{uuid.uuid4().int % 250}.{uuid.uuid4().int % 250}",
                "dst_ip": "10.60.0.1",
                "dst_port": 443,
                "bytes_out": 1024,
                "external_id": f"perf-{uuid.uuid4()}",
            }
            for _ in range(300)
        ]
    }
    start = time.perf_counter()
    response = client.post("/api/v1/telemetry/events/batch", json=batch, headers=INGEST)
    elapsed = time.perf_counter() - start

    assert response.status_code == 202, response.text
    body = response.json()
    assert body["accepted"] == 300
    assert body["rejected"] == 0
    # Very generous ceiling: protects against pathological regressions only.
    assert elapsed < 30, f"batch ingestion took {elapsed:.2f}s"
    print(f"ingested 300 events in {elapsed:.2f}s ({300 / elapsed:.0f} events/s)")


def test_large_page_request_is_capped(client, admin_headers):
    response = client.get("/api/v1/telemetry/events", headers=admin_headers, params={"page_size": 100000})
    assert response.status_code == 422
    capped = client.get("/api/v1/telemetry/events", headers=admin_headers, params={"page_size": 200})
    assert capped.status_code == 200
    assert capped.json()["page_size"] == 200
