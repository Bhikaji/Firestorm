"""Deterministic detection rules.

Every rule is a pure function over an ``EventContext`` so it can be unit
tested with synthetic telemetry and no live sensors. Each rule returns zero
or more ``Detection`` objects carrying the rule id, version, confidence,
severity, MITRE technique hints and the human-readable signals that produced
them.

Rules are intentionally conservative: correlation over single events, explicit
thresholds, and never a claim that a detection proves an attacker's identity.
"""

from __future__ import annotations

import math
from collections import Counter
from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from app.models.telemetry import Event


@dataclass
class Detection:
    rule_id: str
    code: str
    title: str
    description: str
    severity: str
    confidence: float
    signals: list[dict[str, Any]]
    ttps: list[str] = field(default_factory=list)
    recommended_actions: list[str] = field(default_factory=list)
    asset_id: str | None = None
    fingerprint_parts: tuple[str, ...] = ()
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = None
    dns_query: str | None = None

    @property
    def fingerprint(self) -> str:
        parts = self.fingerprint_parts or (self.rule_id, self.src_ip or "-", self.dst_ip or "-")
        return "|".join([self.rule_id, *parts])


@dataclass
class EventContext:
    """Everything a rule may consult. Never performs I/O of its own."""

    event: Event
    related: Sequence[Event] = ()
    asset_criticality: int = 3
    asset_trust_state: str = "unknown"
    asset_id: str | None = None
    threat_match: Any | None = None
    now: datetime = field(default_factory=lambda: datetime.now(UTC))

    def family(self, *event_types: str) -> list[Event]:
        wanted = set(event_types)
        return [e for e in self.related if e.event_type in wanted]

    def from_source(self, src_ip: str | None) -> list[Event]:
        if not src_ip:
            return list(self.related)
        return [e for e in self.related if e.src_ip == src_ip]


RuleFn = Callable[[EventContext], list[Detection]]

RULES: dict[str, RuleFn] = {}
RULE_META: dict[str, dict[str, str]] = {}


def rule(rule_id: str, code: str, version: str = "1.0.0"):
    def decorator(fn: RuleFn) -> RuleFn:
        RULES[rule_id] = fn
        RULE_META[rule_id] = {"code": code, "version": version}
        return fn

    return decorator


def _sig(key: str, label: str, weight: int, detail: str, source: str) -> dict[str, Any]:
    return {"key": key, "label": label, "weight": weight, "detail": detail, "source": source}


# ---------------------------------------------------------------------------
# Malware / endpoint
# ---------------------------------------------------------------------------


@rule("R-0001", "malware_detection")
def malware_detection(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"malware_detected", "av_detection", "edr_detection"}:
        return []
    sig = ev.signature or "unnamed signature"
    return [
        Detection(
            rule_id="R-0001",
            code="malware_detection",
            title=f"Malware detected on {ev.hostname or ev.src_ip or 'endpoint'}",
            description=(
                f"Detection engine '{ev.source}' reported signature '{sig}'"
                + (f" for file {ev.file_name}" if ev.file_name else "")
                + ". Signature hits identify known-bad content; they do not by themselves "
                "establish how the file arrived."
            ),
            severity="critical" if (ev.severity == "critical" or ctx.asset_criticality >= 4) else "high",
            confidence=0.9,
            signals=[
                _sig("malware_signature", "Malware signature", 35, f"Signature: {sig}", ev.source),
                _sig("asset_criticality", f"Asset criticality {ctx.asset_criticality}/5", ctx.asset_criticality * 4,
                     "Higher criticality raises containment urgency", "inventory"),
            ],
            ttps=["T1204", "T1105"],
            recommended_actions=["quarantine_asset", "collect_evidence", "scan_host"],
            asset_id=ctx.asset_id,
            fingerprint_parts=(ctx.asset_id or ev.hostname or ev.src_ip or "unknown", sig),
            src_ip=ev.src_ip,
        )
    ]


@rule("R-0002", "endpoint_protection_disabled")
def endpoint_protection_disabled(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"edr_disabled", "av_disabled", "tamper_protection_off"}:
        return []
    return [
        Detection(
            rule_id="R-0002",
            code="endpoint_protection_disabled",
            title="Endpoint protection disabled or tampered with",
            description=(
                f"Endpoint {ev.hostname or ev.src_ip} reported that a security control was disabled. "
                "Attackers commonly disable endpoint protection before deploying payloads."
            ),
            severity="high",
            confidence=0.75,
            signals=[
                _sig("tamper", "Security control disabled", 30, f"Event: {ev.event_type}", ev.source),
            ],
            ttps=["T1562.001"],
            recommended_actions=["verify_with_endpoint_agent", "collect_evidence", "notify_team"],
            asset_id=ctx.asset_id,
            src_ip=ev.src_ip,
        )
    ]


# ---------------------------------------------------------------------------
# Network behaviour
# ---------------------------------------------------------------------------


@rule("R-0003", "port_scan")
def port_scan(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"network_connection", "firewall_deny", "flow"}:
        return []
    window = [e for e in ctx.from_source(ev.src_ip) if e.dst_port is not None]
    ports = {e.dst_port for e in window}
    hosts = {e.dst_ip for e in window if e.dst_ip}
    if len(ports) >= 15 and len(hosts) >= 1:
        return [
            Detection(
                rule_id="R-0003",
                code="port_scan",
                title=f"Port scanning from {ev.src_ip}",
                description=(
                    f"{len(ports)} distinct destination ports across {len(hosts)} host(s) observed from "
                    f"{ev.src_ip} within the correlation window. Scanning often precedes exploitation."
                ),
                severity="high" if len(ports) >= 40 else "medium",
                confidence=min(0.95, 0.5 + len(ports) / 100),
                signals=[
                    _sig("scan_ports", f"{len(ports)} destination ports", 25, "Port fan-out pattern", "behavior"),
                    _sig("scan_hosts", f"{len(hosts)} destination hosts", 10 * min(len(hosts), 3), "Host sweep pattern", "behavior"),
                ],
                ttps=["T1046"],
                recommended_actions=["investigate_source", "block_ip"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-",),
                src_ip=ev.src_ip,
            )
        ]
    return []


@rule("R-0004", "authentication_bruteforce")
def authentication_bruteforce(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"auth_failure", "login_failure", "authentication_failed"}:
        return []
    failures = [e for e in ctx.from_source(ev.src_ip) if e.event_type in {"auth_failure", "login_failure", "authentication_failed"}]
    users = {e.username for e in failures if e.username}
    if len(failures) >= 8:
        return [
            Detection(
                rule_id="R-0004",
                code="authentication_bruteforce",
                title=f"Repeated authentication failures from {ev.src_ip}",
                description=(
                    f"{len(failures)} failed authentications across {max(len(users), 1)} account(s) observed. "
                    "This may indicate password guessing, credential stuffing, or a misconfigured service account."
                ),
                severity="high" if len(failures) >= 20 else "medium",
                confidence=min(0.92, 0.55 + len(failures) / 60),
                signals=[
                    _sig("auth_failures", f"{len(failures)} failed authentications", 25, "Failure burst", "identity"),
                    _sig("spray", f"{len(users)} targeted accounts", 10 * min(len(users), 3), "Account spray width", "identity"),
                ],
                ttps=["T1110.003"],
                recommended_actions=["investigate_source", "notify_team", "block_ip"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-",),
                src_ip=ev.src_ip,
            )
        ]
    return []


def _entropy(value: str) -> float:
    if not value:
        return 0.0
    counts = Counter(value)
    length = len(value)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


@rule("R-0005", "dns_tunneling")
def dns_tunneling(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type != "dns_query" or not ev.dns_query:
        return []
    queries = [e.dns_query for e in ctx.related if e.event_type == "dns_query" and e.dns_query]
    total = len(queries)
    if total < 20:
        return []
    lens = [len(q) for q in queries]
    avg_len = sum(lens) / len(lens)
    avg_entropy = sum(_entropy(q.split(".")[0]) for q in queries) / len(queries)
    unique = len(set(queries))
    if avg_len >= 40 and avg_entropy >= 3.4 and unique / total >= 0.7:
        return [
            Detection(
                rule_id="R-0005",
                code="dns_tunneling",
                title=f"Possible DNS tunneling via {ev.dns_query.split('.')[-2:]}",
                description=(
                    f"{total} DNS queries with high-entropy labels (avg length {avg_len:.0f}, "
                    f"entropy {avg_entropy:.2f}, {unique} unique) were observed. "
                    "Encoding data in DNS labels is a common exfiltration and C2 technique; "
                    "high entropy alone is not proof of malicious activity."
                ),
                severity="high",
                confidence=min(0.9, 0.5 + avg_entropy / 10),
                signals=[
                    _sig("dns_entropy", f"Label entropy {avg_entropy:.2f}", 30, "High-entropy query labels", "behavior"),
                    _sig("dns_volume", f"{total} queries", 15, "Query volume above baseline", "behavior"),
                ],
                ttps=["T1071.004", "T1048.003"],
                recommended_actions=["investigate_dns", "sinkhole_domain", "collect_evidence"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-", ".".join(ev.dns_query.split(".")[-2:])),
                src_ip=ev.src_ip,
                dns_query=ev.dns_query,
            )
        ]
    return []


@rule("R-0006", "data_exfiltration")
def data_exfiltration(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"flow", "network_connection"}:
        return []
    external = [e for e in ctx.related if e.bytes_out >= 5_000_000]
    if ev.bytes_out < 5_000_000:
        return []
    total_out = sum(e.bytes_out for e in external)
    if total_out < 20_000_000:
        return []
    return [
        Detection(
            rule_id="R-0006",
            code="data_exfiltration",
            title=f"Large outbound transfer from {ev.hostname or ev.src_ip}",
            description=(
                f"{total_out / 1_000_000:.1f} MB sent to external destinations in {len(external)} flow(s). "
                "Volume anomalies require baseline comparison and business context before being "
                "treated as exfiltration."
            ),
            severity="critical" if ctx.asset_criticality >= 4 else "high",
            confidence=0.6,
            signals=[
                _sig("egress_volume", f"{total_out / 1_000_000:.1f} MB egress", 30, "Unusual outbound volume", "behavior"),
                _sig("asset_criticality", f"Asset criticality {ctx.asset_criticality}/5", ctx.asset_criticality * 4,
                     "Data value increases impact", "inventory"),
            ],
            ttps=["T1041"],
            recommended_actions=["collect_evidence", "notify_team", "block_ip"],
            asset_id=ctx.asset_id,
            fingerprint_parts=(ctx.asset_id or ev.src_ip or "-", ev.dst_ip or "-"),
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
        )
    ]


@rule("R-0007", "lateral_movement")
def lateral_movement(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    internal_ports = {445, 139, 3389, 5985, 5986, 22, 135}
    if ev.event_type not in {"network_connection", "flow", "auth_success"}:
        return []
    if ev.dst_port not in internal_ports:
        return []
    peers = {
        e.dst_ip
        for e in ctx.from_source(ev.src_ip)
        if e.dst_port in internal_ports and e.dst_ip and e.dst_ip != ev.src_ip
    }
    if len(peers) >= 4:
        return [
            Detection(
                rule_id="R-0007",
                code="lateral_movement",
                title=f"Lateral movement pattern from {ev.hostname or ev.src_ip}",
                description=(
                    f"Administrative-protocol connections (SMB/RDP/WinRM/SSH) to {len(peers)} internal hosts "
                    "were observed. This resembles lateral movement, but administrative tooling and "
                    "patch management also produce it."
                ),
                severity="high",
                confidence=0.65,
                signals=[
                    _sig("east_west", f"{len(peers)} internal peers", 25, "Internal admin-protocol fan-out", "behavior"),
                ],
                ttps=["T1021.001", "T1021.002"],
                recommended_actions=["investigate_source", "notify_team"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-",),
                src_ip=ev.src_ip,
            )
        ]
    return []


@rule("R-0008", "c2_beaconing")
def c2_beaconing(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"flow", "network_connection"}:
        return []
    if not ev.dst_ip:
        return []
    flows = [e for e in ctx.from_source(ev.src_ip) if e.dst_ip == ev.dst_ip and e.event_type in {"flow", "network_connection"}]
    if len(flows) < 8:
        return []
    times = sorted(e.ts for e in flows)
    intervals = [(b - a).total_seconds() for a, b in zip(times, times[1:], strict=False)]
    if not intervals:
        return []
    mean = sum(intervals) / len(intervals)
    if mean < 5:
        return []
    variance = sum((i - mean) ** 2 for i in intervals) / len(intervals)
    stdev = math.sqrt(variance)
    jitter = stdev / mean
    if jitter <= 0.2 and mean <= 900:
        return [
            Detection(
                rule_id="R-0008",
                code="c2_beaconing",
                title=f"Periodic beaconing to {ev.dst_ip}",
                description=(
                    f"{len(flows)} connections to {ev.dst_ip} at a {mean:.0f}s interval "
                    f"(jitter {jitter:.0%}). Regular beaconing is characteristic of C2 implants, "
                    "but health checks and telemetry agents also poll on fixed intervals."
                ),
                severity="high",
                confidence=0.65,
                signals=[
                    _sig("beacon_regularity", f"{jitter:.0%} jitter", 25, "Low-jitter periodic traffic", "behavior"),
                    _sig("beacon_target", f"Target {ev.dst_ip}", 10, "Repeated single destination", "behavior"),
                ],
                ttps=["T1071", "T1571"],
                recommended_actions=["investigate_destination", "block_ip", "collect_evidence"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-", ev.dst_ip),
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
            )
        ]
    return []


@rule("R-0009", "suspicious_protocol")
def suspicious_protocol(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type != "flow":
        return []
    cleartext = {21, 23, 143, 110, 512, 513, 514}
    if ev.dst_port in cleartext and ev.bytes_out > 1_000_000:
        return [
            Detection(
                rule_id="R-0009",
                code="cleartext_bulk_transfer",
                title=f"Bulk data over cleartext protocol (port {ev.dst_port})",
                description=(
                    f"{ev.bytes_out / 1_000_000:.1f} MB transferred over port {ev.dst_port}, a protocol "
                    "without transport encryption. This is a policy violation and an exposure risk."
                ),
                severity="medium",
                confidence=0.55,
                signals=[_sig("cleartext", "Cleartext bulk transfer", 20, f"Port {ev.dst_port}", "policy")],
                ttps=["T1048"],
                recommended_actions=["notify_team"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(ev.src_ip or "-", str(ev.dst_port)),
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                dst_port=ev.dst_port,
            )
        ]
    return []


# ---------------------------------------------------------------------------
# Threat intelligence / IDS
# ---------------------------------------------------------------------------


@rule("R-0010", "threat_intel_match")
def threat_intel_match(ctx: EventContext) -> list[Detection]:
    match = ctx.threat_match
    if match is None:
        return []
    ev = ctx.event
    target = match.indicator
    return [
        Detection(
            rule_id="R-0010",
            code="threat_intel_match",
            title=f"Known-bad indicator contacted: {target}",
            description=(
                f"Traffic matched the {match.indicator_type} indicator '{target}' "
                f"(category {match.category}, source {match.source}, confidence {match.confidence}%). "
                "A feed match indicates historical reputation, not proof of compromise."
            ),
            severity="critical" if match.confidence >= 85 else "high",
            confidence=min(0.95, match.confidence / 100),
            signals=[
                _sig("ti_match", f"Threat feed match ({match.source})", 30,
                     f"{match.indicator_type}: {target}", "threat_intel"),
                _sig("ti_confidence", f"Indicator confidence {match.confidence}%", int(match.confidence / 5),
                     match.category, "threat_intel"),
            ],
            ttps=["T1071"],
            recommended_actions=["block_ip", "collect_evidence", "investigate_destination"],
            asset_id=ctx.asset_id,
            fingerprint_parts=(target, ctx.asset_id or ev.src_ip or "-"),
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            dns_query=ev.dns_query,
        )
    ]


@rule("R-0011", "ids_signature")
def ids_signature(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.source != "suricata" or ev.event_type not in {"ids_alert", "intrusion_attempt"}:
        return []
    if not ev.signature:
        return []
    sev = {"critical": "critical", "high": "high", "medium": "medium"}.get(ev.severity, "low")
    return [
        Detection(
            rule_id="R-0011",
            code="ids_signature",
            title=f"IDS signature: {ev.signature}",
            description=(
                f"Suricata signature '{ev.signature}' fired between {ev.src_ip} and {ev.dst_ip}. "
                "Signature-based detection is precise for known attacks but blind to novel ones, "
                "and can fire on benign traffic (for example vulnerability scanners)."
            ),
            severity=sev,
            confidence=0.7 if sev in {"high", "critical"} else 0.5,
            signals=[_sig("ids_sig", "IDS signature match", 20, ev.signature, "suricata")],
            ttps=["T1190"],
            recommended_actions=["investigate_destination", "collect_evidence"],
            asset_id=ctx.asset_id,
            fingerprint_parts=(ev.signature, ev.src_ip or "-"),
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            dst_port=ev.dst_port,
        )
    ]


@rule("R-0012", "phishing_email")
def phishing_email(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type != "email_received":
        return []
    raw = ev.raw or {}
    failed = [
        proto.upper()
        for proto in ("spf", "dkim", "dmarc")
        if str(raw.get(proto, "")).lower() in {"fail", "softfail", "none", "permerror"}
    ]
    urls = raw.get("urls") or []
    if len(failed) >= 2 or (failed and urls):
        return [
            Detection(
                rule_id="R-0012",
                code="phishing_email",
                title=f"Suspicious email: {raw.get('subject', 'no subject')}",
                description=(
                    f"Email from {raw.get('from', 'unknown sender')} failed {', '.join(failed) or 'no'} "
                    f"authentication checks with {len(urls)} embedded link(s). "
                    "Authentication failures increase suspicion but do not prove malicious intent; "
                    "forwarding and misconfiguration produce false positives."
                ),
                severity="high" if len(failed) >= 2 and urls else "medium",
                confidence=0.6,
                signals=[
                    _sig("email_auth", f"Failed: {', '.join(failed) or 'n/a'}", 20, "SPF/DKIM/DMARC failure", "identity"),
                    _sig("email_urls", f"{len(urls)} embedded links", 10, "Links present in body", "email"),
                ],
                ttps=["T1566.002"],
                recommended_actions=["collect_evidence", "notify_team"],
                asset_id=ctx.asset_id,
                fingerprint_parts=(str(raw.get("message_id", ev.id)),),
                src_ip=ev.src_ip,
            )
        ]
    return []


@rule("R-0013", "unknown_device_access")
def unknown_device_access(ctx: EventContext) -> list[Detection]:
    ev = ctx.event
    if ev.event_type not in {"network_connection", "admission_denied", "auth_success"}:
        return []
    if ctx.asset_id is not None and ctx.asset_trust_state != "unknown":
        return []
    if ev.dst_port not in {22, 3389, 445, 5432, 3306, 8080, 8443, 9200}:
        return []
    return [
        Detection(
            rule_id="R-0013",
            code="unknown_device_access",
            title=f"Unregistered device accessing administrative service ({ev.src_ip})",
            description=(
                f"Source {ev.src_ip} is not present in the authorised device inventory and attempted "
                f"to reach port {ev.dst_port}. Unregistered devices belong on the registration VLAN "
                "until identity is established."
            ),
            severity="medium",
            confidence=0.6,
            signals=[
                _sig("unknown_asset", "Device not in inventory", 20, f"{ev.src_ip} unregistered", "inventory"),
                _sig("admin_service", f"Administrative port {ev.dst_port}", 15, "Sensitive service target", "network"),
            ],
            ttps=["T1021"],
            recommended_actions=["investigate_source", "notify_team"],
            fingerprint_parts=(ev.src_ip or "-", str(ev.dst_port)),
            src_ip=ev.src_ip,
            dst_ip=ev.dst_ip,
            dst_port=ev.dst_port,
        )
    ]


# Ordered evaluation. R-0010 (threat intel) runs first because a feed match is
# the strongest single signal and other rules should not mask it.
EVAL_ORDER = ["R-0010", "R-0001", "R-0002", "R-0012", "R-0005", "R-0008", "R-0006", "R-0007",
              "R-0003", "R-0004", "R-0011", "R-0009", "R-0013"]


def evaluate(ctx: EventContext, *, rule_ids: Iterable[str] | None = None) -> list[Detection]:
    detections: list[Detection] = []
    for rule_id in rule_ids or EVAL_ORDER:
        fn = RULES.get(rule_id)
        if not fn:
            continue
        try:
            detections.extend(fn(ctx))
        except Exception:  # a broken rule must not stop the pipeline
            import logging

            logging.getLogger("firestorm.detection").exception("rule %s failed", rule_id)
    return detections


def rules_catalog() -> list[dict[str, str]]:
    return [
        {
            "rule_id": rid,
            "code": RULE_META[rid]["code"],
            "version": RULE_META[rid]["version"],
            "description": (fn.__doc__ or "").strip().split("\n")[0],
        }
        for rid, fn in RULES.items()
    ]
