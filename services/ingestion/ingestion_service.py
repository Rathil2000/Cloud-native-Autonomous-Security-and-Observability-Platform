"""
Data Ingestion Service
Collects metrics from Prometheus, logs from Fluent Bit,
and Falco security events — then publishes them to Kafka topics.

Run: python ingestion_service.py
"""

from __future__ import annotations
import asyncio
import json
import logging
import os
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

import requests
from kafka import KafkaProducer
from kafka.errors import KafkaError

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s [%(name)s] %(message)s",
)
logger = logging.getLogger("ingestion")

# ── Config (override via env vars) ───────────────────────────
KAFKA_BOOTSTRAP = os.getenv("KAFKA_BOOTSTRAP_SERVERS", "localhost:9092")
PROMETHEUS_URL = os.getenv("PROMETHEUS_URL", "http://localhost:9090")
SCRAPE_INTERVAL_SEC = int(os.getenv("SCRAPE_INTERVAL_SEC", "15"))

TOPICS = {
    "metrics": "metrics-raw",
    "logs": "logs-raw",
    "security": "security-events-raw",
    "traces": "traces-raw",
}


# ── Data Models ───────────────────────────────────────────────

@dataclass
class MetricEvent:
    timestamp: str
    service_name: str
    namespace: str
    pod_name: str
    cpu_usage: float
    memory_usage: float
    network_in_bytes: float
    network_out_bytes: float
    disk_read_iops: float
    disk_write_iops: float
    http_request_rate: float
    http_error_rate: float
    pod_restart_count: int
    latency_p95_ms: float
    source: str = "prometheus"


@dataclass
class LogEvent:
    timestamp: str
    service_name: str
    namespace: str
    pod_name: str
    level: str
    message: str
    trace_id: str = ""
    span_id: str = ""
    source: str = "fluent-bit"
    raw: dict = field(default_factory=dict)


@dataclass
class SecurityEvent:
    timestamp: str
    rule_name: str
    priority: str
    message: str
    pod_name: str
    namespace: str
    container_id: str = ""
    process_name: str = ""
    syscall: str = ""
    source: str = "falco"


# ── Kafka Producer ────────────────────────────────────────────

def create_producer() -> KafkaProducer:
    return KafkaProducer(
        bootstrap_servers=KAFKA_BOOTSTRAP,
        value_serializer=lambda v: json.dumps(v).encode("utf-8"),
        key_serializer=lambda k: k.encode("utf-8") if k else None,
        acks="all",                    # wait for all replicas
        retries=5,
        max_in_flight_requests_per_connection=1,  # preserve order
        compression_type="gzip",
        linger_ms=10,                  # small batching window
    )


def publish(producer: KafkaProducer, topic: str, key: str, payload: dict) -> None:
    future = producer.send(topic, key=key, value=payload)
    try:
        future.get(timeout=10)
    except KafkaError as e:
        logger.error("Failed to publish to %s: %s", topic, e)


# ── Prometheus Scraper ────────────────────────────────────────

PROM_QUERIES = {
    "cpu_usage":          'sum(rate(container_cpu_usage_seconds_total[1m])) by (pod, namespace) * 100',
    "memory_usage":       'sum(container_memory_working_set_bytes) by (pod, namespace) / sum(container_spec_memory_limit_bytes) by (pod, namespace) * 100',
    "http_request_rate":  'sum(rate(http_requests_total[1m])) by (pod, namespace)',
    "http_error_rate":    'sum(rate(http_requests_total{status=~"5.."}[1m])) by (pod, namespace) / sum(rate(http_requests_total[1m])) by (pod, namespace)',
    "pod_restart_count":  'sum(kube_pod_container_status_restarts_total) by (pod, namespace)',
    "latency_p95_ms":     'histogram_quantile(0.95, sum(rate(http_request_duration_seconds_bucket[5m])) by (le, pod, namespace)) * 1000',
}


def scrape_prometheus() -> list[MetricEvent]:
    events = []
    results_by_pod: dict[tuple, dict] = {}

    for metric_name, query in PROM_QUERIES.items():
        try:
            resp = requests.get(
                f"{PROMETHEUS_URL}/api/v1/query",
                params={"query": query},
                timeout=10,
            )
            resp.raise_for_status()
            data = resp.json()

            for result in data.get("data", {}).get("result", []):
                pod = result["metric"].get("pod", "unknown")
                ns = result["metric"].get("namespace", "default")
                key = (pod, ns)
                if key not in results_by_pod:
                    results_by_pod[key] = {"pod_name": pod, "namespace": ns}
                try:
                    results_by_pod[key][metric_name] = float(result["value"][1])
                except (ValueError, IndexError):
                    results_by_pod[key][metric_name] = 0.0

        except requests.RequestException as e:
            logger.warning("Prometheus scrape failed for %s: %s", metric_name, e)

    ts = datetime.now(timezone.utc).isoformat()
    for (pod, ns), vals in results_by_pod.items():
        service = pod.rsplit("-", 2)[0] if pod.count("-") >= 2 else pod
        events.append(MetricEvent(
            timestamp=ts,
            service_name=service,
            namespace=ns,
            pod_name=pod,
            cpu_usage=vals.get("cpu_usage", 0.0),
            memory_usage=vals.get("memory_usage", 0.0),
            network_in_bytes=vals.get("network_in_bytes", 0.0),
            network_out_bytes=vals.get("network_out_bytes", 0.0),
            disk_read_iops=vals.get("disk_read_iops", 0.0),
            disk_write_iops=vals.get("disk_write_iops", 0.0),
            http_request_rate=vals.get("http_request_rate", 0.0),
            http_error_rate=vals.get("http_error_rate", 0.0),
            pod_restart_count=int(vals.get("pod_restart_count", 0)),
            latency_p95_ms=vals.get("latency_p95_ms", 0.0),
        ))

    return events


# ── Main Ingestion Loop ───────────────────────────────────────

async def metrics_ingestion_loop(producer: KafkaProducer) -> None:
    logger.info("Starting metrics ingestion loop (interval=%ds) …", SCRAPE_INTERVAL_SEC)
    while True:
        start = time.perf_counter()
        events = scrape_prometheus()
        for event in events:
            payload = asdict(event)
            publish(producer, TOPICS["metrics"], event.pod_name, payload)
        elapsed = time.perf_counter() - start
        logger.info("Ingested %d metric events in %.2fs", len(events), elapsed)
        await asyncio.sleep(SCRAPE_INTERVAL_SEC)


async def main():
    logger.info("Connecting to Kafka at %s …", KAFKA_BOOTSTRAP)
    producer = create_producer()
    logger.info("Kafka producer connected ✓")

    await asyncio.gather(
        metrics_ingestion_loop(producer),
    )


if __name__ == "__main__":
    asyncio.run(main())
