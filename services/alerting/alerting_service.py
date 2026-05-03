"""
Alerting Service
Consumes threat events from Kafka, classifies severity,
deduplicates, and routes to PagerDuty / Slack / JIRA.

Run: python alerting_service.py
"""

from __future__ import annotations
import hashlib
import json
import logging
import os
import time
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from enum import Enum

import requests
from kafka import KafkaConsumer, KafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("alerting")

# ── Config ─────────────────────────────────────────────────────
KAFKA_BOOTSTRAP      = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
SLACK_WEBHOOK_URL    = os.getenv("SLACK_WEBHOOK_URL", "")
PAGERDUTY_ROUTING_KEY = os.getenv("PAGERDUTY_ROUTING_KEY", "")
JIRA_BASE_URL        = os.getenv("JIRA_BASE_URL", "")
JIRA_API_TOKEN       = os.getenv("JIRA_API_TOKEN", "")
JIRA_PROJECT_KEY     = os.getenv("JIRA_PROJECT_KEY", "SEC")

THREAT_TOPIC  = "threat-events"
ALERT_TOPIC   = "alerts-processed"
CONSUMER_GROUP = "alerting-service"

# Dedup window in seconds
DEDUP_TTL_SEC = 300


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    NONE     = "NONE"


@dataclass
class Alert:
    alert_id: str
    timestamp: str
    severity: Severity
    title: str
    description: str
    service_name: str
    namespace: str
    mitre_tactic: str
    mitre_technique: str
    source_type: str   # "metric_anomaly" | "log_anomaly" | "falco_rule"
    raw_score: float
    routed_to: list[str]
    status: str = "OPEN"


# ── Dedup Cache (in-memory for simplicity; use Redis in prod) ──

_dedup_cache: dict[str, float] = {}

def _is_duplicate(fingerprint: str) -> bool:
    now = time.monotonic()
    if fingerprint in _dedup_cache:
        if now - _dedup_cache[fingerprint] < DEDUP_TTL_SEC:
            return True
    _dedup_cache[fingerprint] = now
    # Prune stale entries
    for k in list(_dedup_cache):
        if now - _dedup_cache[k] > DEDUP_TTL_SEC:
            del _dedup_cache[k]
    return False

def _fingerprint(event: dict) -> str:
    key = f"{event.get('service_name')}:{event.get('rule_name', event.get('anomaly_type', ''))}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


# ── MITRE ATT&CK Mapping ──────────────────────────────────────

MITRE_MAP = {
    "high_cpu_anomaly":          ("Impact",          "T1496 - Resource Hijacking"),
    "high_network_out":          ("Exfiltration",    "T1041 - Exfiltration Over C2 Channel"),
    "high_http_error_rate":      ("Impact",          "T1499 - Endpoint Denial of Service"),
    "pod_restart_anomaly":       ("Persistence",     "T1525 - Implant Container Image"),
    "container_escape":          ("Privilege Escalation", "T1611 - Escape to Host"),
    "unexpected_process":        ("Execution",       "T1059 - Command and Scripting Interpreter"),
    "network_scan":              ("Discovery",       "T1046 - Network Service Discovery"),
    "credential_access":         ("Credential Access", "T1552 - Unsecured Credentials"),
    "log_sequence_anomaly":      ("Lateral Movement", "T1210 - Exploitation of Remote Services"),
}

def _get_mitre(source_key: str) -> tuple[str, str]:
    return MITRE_MAP.get(source_key, ("Unknown", "Unknown"))


# ── Routing Functions ─────────────────────────────────────────

def route_to_slack(alert: Alert, webhook_url: str) -> bool:
    if not webhook_url:
        logger.debug("Slack webhook not configured, skipping")
        return False
    emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(alert.severity, "⚪")
    payload = {
        "text": f"{emoji} *[{alert.severity}] {alert.title}*",
        "attachments": [{
            "color": {"CRITICAL": "danger", "HIGH": "warning", "MEDIUM": "#f0ad4e", "LOW": "good"}.get(alert.severity, "#ccc"),
            "fields": [
                {"title": "Service",    "value": alert.service_name, "short": True},
                {"title": "Namespace",  "value": alert.namespace,    "short": True},
                {"title": "MITRE",      "value": f"{alert.mitre_tactic} / {alert.mitre_technique}", "short": False},
                {"title": "Description","value": alert.description,  "short": False},
                {"title": "Alert ID",   "value": alert.alert_id,     "short": True},
                {"title": "Timestamp",  "value": alert.timestamp,    "short": True},
            ],
        }],
    }
    try:
        r = requests.post(webhook_url, json=payload, timeout=5)
        r.raise_for_status()
        logger.info("Slack notified for alert %s", alert.alert_id)
        return True
    except Exception as e:
        logger.error("Slack notification failed: %s", e)
        return False


def route_to_pagerduty(alert: Alert, routing_key: str) -> bool:
    if not routing_key:
        return False
    payload = {
        "routing_key": routing_key,
        "event_action": "trigger",
        "dedup_key": alert.alert_id,
        "payload": {
            "summary": f"[{alert.severity}] {alert.title}",
            "source": f"{alert.namespace}/{alert.service_name}",
            "severity": alert.severity.lower().replace("critical", "critical"),
            "timestamp": alert.timestamp,
            "custom_details": {
                "description":      alert.description,
                "mitre_tactic":     alert.mitre_tactic,
                "mitre_technique":  alert.mitre_technique,
                "raw_score":        alert.raw_score,
                "source_type":      alert.source_type,
            },
        },
    }
    try:
        r = requests.post(
            "https://events.pagerduty.com/v2/enqueue",
            json=payload, timeout=5,
        )
        r.raise_for_status()
        logger.info("PagerDuty incident triggered for alert %s", alert.alert_id)
        return True
    except Exception as e:
        logger.error("PagerDuty routing failed: %s", e)
        return False


def create_jira_ticket(alert: Alert) -> bool:
    if not JIRA_BASE_URL or not JIRA_API_TOKEN:
        return False
    ticket = {
        "fields": {
            "project": {"key": JIRA_PROJECT_KEY},
            "summary": f"[{alert.severity}] {alert.title} — {alert.service_name}",
            "description": {
                "type": "doc", "version": 1,
                "content": [{"type": "paragraph", "content": [
                    {"type": "text", "text": alert.description}
                ]}],
            },
            "issuetype": {"name": "Bug"},
            "priority": {"name": {
                "CRITICAL": "Highest", "HIGH": "High",
                "MEDIUM": "Medium", "LOW": "Low",
            }.get(alert.severity, "Medium")},
            "labels": ["security", "auto-generated", alert.source_type],
        }
    }
    try:
        r = requests.post(
            f"{JIRA_BASE_URL}/rest/api/3/issue",
            json=ticket,
            headers={
                "Authorization": f"Bearer {JIRA_API_TOKEN}",
                "Content-Type": "application/json",
            },
            timeout=10,
        )
        r.raise_for_status()
        issue_key = r.json().get("key", "?")
        logger.info("JIRA ticket %s created for alert %s", issue_key, alert.alert_id)
        return True
    except Exception as e:
        logger.error("JIRA ticket creation failed: %s", e)
        return False


# ── Event Processor ───────────────────────────────────────────

def process_threat_event(event: dict) -> Alert | None:
    fingerprint = _fingerprint(event)
    if _is_duplicate(fingerprint):
        logger.debug("Duplicate event suppressed: %s", fingerprint)
        return None

    severity_str = event.get("severity", "LOW")
    try:
        severity = Severity(severity_str)
    except ValueError:
        severity = Severity.LOW

    source_key = event.get("anomaly_type") or event.get("rule_name", "unknown")
    tactic, technique = _get_mitre(source_key)

    alert = Alert(
        alert_id=f"ALT-{fingerprint}-{int(time.time())}",
        timestamp=event.get("timestamp", datetime.now(timezone.utc).isoformat()),
        severity=severity,
        title=f"{source_key.replace('_', ' ').title()} detected",
        description=event.get("message", "Anomalous behaviour detected by the security platform."),
        service_name=event.get("service_name", "unknown"),
        namespace=event.get("namespace", "default"),
        mitre_tactic=tactic,
        mitre_technique=technique,
        source_type=event.get("source_type", "unknown"),
        raw_score=float(event.get("anomaly_score", 0.0)),
        routed_to=[],
    )

    # Route based on severity
    if severity == Severity.CRITICAL:
        if route_to_pagerduty(alert, PAGERDUTY_ROUTING_KEY):
            alert.routed_to.append("pagerduty")
        if route_to_slack(alert, SLACK_WEBHOOK_URL):
            alert.routed_to.append("slack")
        if create_jira_ticket(alert):
            alert.routed_to.append("jira")

    elif severity == Severity.HIGH:
        if route_to_slack(alert, SLACK_WEBHOOK_URL):
            alert.routed_to.append("slack")
        if create_jira_ticket(alert):
            alert.routed_to.append("jira")

    elif severity == Severity.MEDIUM:
        if route_to_slack(alert, SLACK_WEBHOOK_URL):
            alert.routed_to.append("slack")

    logger.info("Alert %s [%s] routed to: %s", alert.alert_id, severity, alert.routed_to or ["none"])
    return alert


# ── Main Consumer Loop ────────────────────────────────────────

def run():
    logger.info("Connecting Kafka consumer to %s, group=%s …", KAFKA_BOOTSTRAP, CONSUMER_GROUP)
    consumer = KafkaConsumer(
        THREAT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
    )

    logger.info("Alerting service listening on topic '%s' …", THREAT_TOPIC)
    for msg in consumer:
        try:
            event = msg.value
            alert = process_threat_event(event)
            if alert:
                producer.send(ALERT_TOPIC, value=asdict(alert))
        except Exception as e:
            logger.error("Error processing message: %s", e)


if __name__ == "__main__":
    run()
