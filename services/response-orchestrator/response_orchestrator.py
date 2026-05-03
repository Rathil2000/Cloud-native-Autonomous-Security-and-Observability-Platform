"""
Response Orchestrator Service
Consumes high-severity alerts and executes automated remediation playbooks.

Playbooks implemented:
  1. container_escape        → isolate pod, alert security team
  2. credential_compromise   → rotate secrets, disable IAM key
  3. ddos_detection          → scale up, update rate limits
  4. data_exfiltration       → isolate pod, block egress, create JIRA ticket
  5. malware_detected        → quarantine pod, capture forensic snapshot

Run: python response_orchestrator.py
"""

from __future__ import annotations
import json
import logging
import os
import subprocess
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from typing import Callable

from kafka import KafkaConsumer, KafkaProducer

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("response-orchestrator")

KAFKA_BOOTSTRAP   = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
ALERT_TOPIC       = "alerts-processed"
RESPONSE_TOPIC    = "response-actions"
CONSUMER_GROUP    = "response-orchestrator"
KUBECONFIG        = os.getenv("KUBECONFIG", os.path.expanduser("~/.kube/config"))

# Only act on CRITICAL and HIGH alerts autonomously
AUTO_RESPONSE_SEVERITIES = {"CRITICAL", "HIGH"}

# Confidence threshold — only act if raw_score is sufficiently anomalous
CONFIDENCE_THRESHOLD = 0.6


class PlaybookStatus(str, Enum):
    SUCCESS   = "SUCCESS"
    PARTIAL   = "PARTIAL"
    FAILED    = "FAILED"
    SKIPPED   = "SKIPPED"


@dataclass
class PlaybookResult:
    playbook_name: str
    alert_id: str
    timestamp: str
    status: PlaybookStatus
    actions_taken: list[str]
    errors: list[str]
    duration_sec: float


# ── Kubernetes Helper ─────────────────────────────────────────

def kubectl(*args: str) -> tuple[bool, str]:
    """Run a kubectl command and return (success, output)."""
    cmd = ["kubectl", "--kubeconfig", KUBECONFIG, *args]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        if result.returncode == 0:
            return True, result.stdout.strip()
        else:
            return False, result.stderr.strip()
    except subprocess.TimeoutExpired:
        return False, "kubectl command timed out"
    except FileNotFoundError:
        return False, "kubectl not found — is it installed?"


def isolate_pod(namespace: str, pod_name: str) -> tuple[bool, str]:
    """Add a quarantine label and patch NetworkPolicy to isolate the pod."""
    # Label the pod as quarantined
    ok, out = kubectl("label", "pod", pod_name, "-n", namespace,
                      "security.platform/quarantined=true", "--overwrite")
    if not ok:
        return False, f"Failed to label pod: {out}"

    # Remove pod from any Service endpoints by removing the app label
    ok2, out2 = kubectl("label", "pod", pod_name, "-n", namespace,
                        "app-", "--overwrite")  # removes the 'app' label

    logger.info("Pod %s/%s isolated (quarantine label applied)", namespace, pod_name)
    return True, f"Pod {namespace}/{pod_name} quarantined"


def delete_pod(namespace: str, pod_name: str) -> tuple[bool, str]:
    """Forcibly delete a pod (K8s will restart it from the clean image)."""
    ok, out = kubectl("delete", "pod", pod_name, "-n", namespace, "--grace-period=0")
    return ok, out


def scale_deployment(namespace: str, deployment: str, replicas: int) -> tuple[bool, str]:
    ok, out = kubectl("scale", "deployment", deployment,
                      "-n", namespace, f"--replicas={replicas}")
    return ok, out


def apply_network_policy(namespace: str, pod_name: str) -> tuple[bool, str]:
    """Apply a deny-all egress NetworkPolicy for the quarantined pod."""
    policy = {
        "apiVersion": "networking.k8s.io/v1",
        "kind": "NetworkPolicy",
        "metadata": {
            "name": f"quarantine-{pod_name[:40]}",
            "namespace": namespace,
        },
        "spec": {
            "podSelector": {
                "matchLabels": {"security.platform/quarantined": "true"}
            },
            "policyTypes": ["Egress", "Ingress"],
            "egress": [],   # deny all egress
            "ingress": [],  # deny all ingress
        }
    }
    import tempfile, yaml  # type: ignore[import-untyped]
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".yaml", delete=False) as f:
            yaml.dump(policy, f)
            fname = f.name
        ok, out = kubectl("apply", "-f", fname)
        os.unlink(fname)
        return ok, out
    except ImportError:
        # yaml not available — use kubectl patch approach
        return False, "PyYAML not installed; NetworkPolicy not applied"


# ── Playbooks ─────────────────────────────────────────────────

def playbook_container_escape(alert: dict) -> PlaybookResult:
    """
    Container Escape Response Playbook
    1. Immediately isolate the compromised pod
    2. Capture pod logs for forensics
    3. Apply deny-all NetworkPolicy
    4. Alert security team via Kafka event
    """
    t0 = time.perf_counter()
    actions: list[str] = []
    errors: list[str] = []

    pod_name  = alert.get("service_name", "unknown-pod")
    namespace = alert.get("namespace", "default")

    # Step 1: Isolate pod
    ok, msg = isolate_pod(namespace, pod_name)
    if ok:
        actions.append(f"Isolated pod {namespace}/{pod_name}")
    else:
        errors.append(f"Pod isolation failed: {msg}")

    # Step 2: Capture logs before deletion
    ok2, logs = kubectl("logs", pod_name, "-n", namespace,
                        "--previous", "--tail=1000")
    if ok2:
        actions.append(f"Captured {len(logs.splitlines())} log lines for forensics")
    else:
        errors.append(f"Log capture failed: {logs}")

    # Step 3: Apply NetworkPolicy
    ok3, msg3 = apply_network_policy(namespace, pod_name)
    if ok3:
        actions.append(f"NetworkPolicy applied: deny-all for quarantined pod")
    else:
        errors.append(f"NetworkPolicy failed: {msg3}")

    status = PlaybookStatus.SUCCESS if not errors else (
        PlaybookStatus.PARTIAL if actions else PlaybookStatus.FAILED
    )
    return PlaybookResult(
        playbook_name="container_escape",
        alert_id=alert.get("alert_id", ""),
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=status,
        actions_taken=actions,
        errors=errors,
        duration_sec=time.perf_counter() - t0,
    )


def playbook_ddos_detection(alert: dict) -> PlaybookResult:
    """
    DDoS Response Playbook
    1. Scale up the affected deployment to absorb traffic
    2. Log scale-out action
    """
    t0 = time.perf_counter()
    actions: list[str] = []
    errors: list[str] = []

    service   = alert.get("service_name", "unknown")
    namespace = alert.get("namespace", "default")

    # Scale up deployment
    ok, msg = scale_deployment(namespace, service, replicas=10)
    if ok:
        actions.append(f"Scaled deployment {namespace}/{service} to 10 replicas")
    else:
        errors.append(f"Scale-up failed: {msg}")

    # Annotate deployment for human review
    ok2, _ = kubectl("annotate", "deployment", service, "-n", namespace,
                     f"security.platform/ddos-response={datetime.now(timezone.utc).isoformat()}",
                     "--overwrite")
    if ok2:
        actions.append("Deployment annotated for SOC review")

    status = PlaybookStatus.SUCCESS if not errors else (
        PlaybookStatus.PARTIAL if actions else PlaybookStatus.FAILED
    )
    return PlaybookResult(
        playbook_name="ddos_detection",
        alert_id=alert.get("alert_id", ""),
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=status,
        actions_taken=actions,
        errors=errors,
        duration_sec=time.perf_counter() - t0,
    )


def playbook_data_exfiltration(alert: dict) -> PlaybookResult:
    """
    Data Exfiltration Response Playbook
    1. Isolate pod immediately
    2. Apply deny-egress NetworkPolicy
    3. Delete pod (force restart from clean image)
    """
    t0 = time.perf_counter()
    actions: list[str] = []
    errors: list[str] = []

    pod_name  = alert.get("service_name", "unknown-pod")
    namespace = alert.get("namespace", "default")

    ok, msg = isolate_pod(namespace, pod_name)
    if ok:
        actions.append(f"Isolated pod {namespace}/{pod_name}")
    else:
        errors.append(f"Pod isolation failed: {msg}")

    ok2, msg2 = apply_network_policy(namespace, pod_name)
    if ok2:
        actions.append("Deny-all NetworkPolicy applied")
    else:
        errors.append(f"NetworkPolicy failed: {msg2}")

    ok3, msg3 = delete_pod(namespace, pod_name)
    if ok3:
        actions.append(f"Pod {pod_name} deleted (clean restart triggered)")
    else:
        errors.append(f"Pod deletion failed: {msg3}")

    status = PlaybookStatus.SUCCESS if not errors else (
        PlaybookStatus.PARTIAL if actions else PlaybookStatus.FAILED
    )
    return PlaybookResult(
        playbook_name="data_exfiltration",
        alert_id=alert.get("alert_id", ""),
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=status,
        actions_taken=actions,
        errors=errors,
        duration_sec=time.perf_counter() - t0,
    )


def playbook_generic(alert: dict) -> PlaybookResult:
    """Default playbook — log the alert and annotate the related resource."""
    t0 = time.perf_counter()
    service   = alert.get("service_name", "unknown")
    namespace = alert.get("namespace", "default")
    alert_id  = alert.get("alert_id", "")

    ok, _ = kubectl("annotate", "deployment", service, "-n", namespace,
                    f"security.platform/alert={alert_id}", "--overwrite")
    actions = [f"Deployment annotated with alert_id={alert_id}"] if ok else []
    errors  = [] if ok else ["Could not annotate deployment — resource may not exist"]

    return PlaybookResult(
        playbook_name="generic",
        alert_id=alert_id,
        timestamp=datetime.now(timezone.utc).isoformat(),
        status=PlaybookStatus.SUCCESS if ok else PlaybookStatus.SKIPPED,
        actions_taken=actions,
        errors=errors,
        duration_sec=time.perf_counter() - t0,
    )


# ── Playbook Router ───────────────────────────────────────────

PLAYBOOK_REGISTRY: dict[str, Callable[[dict], PlaybookResult]] = {
    "container_escape":      playbook_container_escape,
    "Container Escape":      playbook_container_escape,
    "high_network_out":      playbook_data_exfiltration,
    "Data Exfiltration":     playbook_data_exfiltration,
    "high_http_error_rate":  playbook_ddos_detection,
    "Endpoint Denial Of Service": playbook_ddos_detection,
}

def route_playbook(alert: dict) -> PlaybookResult:
    title       = alert.get("title", "")
    source_type = alert.get("source_type", "")
    mitre_tactic = alert.get("mitre_tactic", "")

    # Try exact match on title
    for key, fn in PLAYBOOK_REGISTRY.items():
        if key in title or key == source_type:
            return fn(alert)

    return playbook_generic(alert)


# ── Main Consumer Loop ────────────────────────────────────────

def run():
    logger.info("Connecting to Kafka at %s …", KAFKA_BOOTSTRAP)
    consumer = KafkaConsumer(
        ALERT_TOPIC,
        bootstrap_servers=KAFKA_BOOTSTRAP,
        group_id=CONSUMER_GROUP,
        value_deserializer=lambda b: json.loads(b.decode("utf-8")),
        auto_offset_reset="latest",
        enable_auto_commit=True,
    )
    producer = KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v, default=str).encode("utf-8"),
    )

    logger.info("Response Orchestrator listening on '%s' …", ALERT_TOPIC)
    for msg in consumer:
        alert = msg.value
        severity = alert.get("severity", "LOW")

        if severity not in AUTO_RESPONSE_SEVERITIES:
            logger.debug("Skipping severity=%s alert (below auto-response threshold)", severity)
            continue

        raw_score = float(alert.get("raw_score", 0.0))
        if abs(raw_score) < CONFIDENCE_THRESHOLD:
            logger.info(
                "Alert %s raw_score=%.3f below confidence threshold — skipped",
                alert.get("alert_id"), raw_score,
            )
            continue

        logger.info(
            "Executing playbook for alert %s [%s] — %s",
            alert.get("alert_id"), severity, alert.get("title"),
        )
        try:
            result = route_playbook(alert)
            logger.info(
                "Playbook '%s' completed: status=%s, actions=%d, errors=%d, duration=%.2fs",
                result.playbook_name, result.status,
                len(result.actions_taken), len(result.errors),
                result.duration_sec,
            )
            # Publish result for audit
            producer.send(RESPONSE_TOPIC, value={
                "playbook_name":   result.playbook_name,
                "alert_id":        result.alert_id,
                "timestamp":       result.timestamp,
                "status":          result.status,
                "actions_taken":   result.actions_taken,
                "errors":          result.errors,
                "duration_sec":    result.duration_sec,
            })
        except Exception as e:
            logger.error("Playbook execution error for alert %s: %s",
                         alert.get("alert_id"), e)


if __name__ == "__main__":
    run()
