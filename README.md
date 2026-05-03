# Cloud-native Autonomous Security and Observability Platform
### TCS iON AIP 225 — Industry Project

A production-grade cloud-native platform for real-time security monitoring, AI-powered anomaly detection, and automated incident response on Kubernetes/AWS.

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│  Layer 4: Presentation & Response                           │
│  Grafana Dashboards | AlertManager | Response Orchestrator  │
├─────────────────────────────────────────────────────────────┤
│  Layer 3: Processing & Detection Engine                     │
│  Apache Flink | ML Engine (IsolationForest+LSTM) | ES       │
├─────────────────────────────────────────────────────────────┤
│  Layer 2: Data Ingestion                                    │
│  Fluent Bit | Prometheus Exporters | OTel | Falco → Kafka   │
├─────────────────────────────────────────────────────────────┤
│  Layer 1: Data Sources                                      │
│  K8s Pods/Nodes | AWS Services | Network | Threat Intel     │
└─────────────────────────────────────────────────────────────┘
```

## Tech Stack

| Category | Tools |
|---|---|
| Container Runtime | Docker 24.x |
| Orchestration | Kubernetes (EKS) + Helm |
| Metrics | Prometheus + AlertManager |
| Visualisation | Grafana |
| Log Pipeline | Fluent Bit → Kafka → Elasticsearch |
| Tracing | Jaeger + OpenTelemetry |
| Stream Processing | Apache Kafka + Apache Flink |
| Runtime Security | Falco + OPA |
| AI/ML | Python, scikit-learn, TensorFlow |
| Secrets | HashiCorp Vault |
| Cloud Platform | AWS (EKS, S3, IAM, VPC) |

---

## Quick Start (Local Development)

### Prerequisites
- Docker Desktop with Kubernetes enabled, OR
- [KIND](https://kind.sigs.k8s.io/) (Kubernetes IN Docker)
- `kubectl`, `helm`, `python3.10+`

### 1. Start local Kubernetes cluster
```bash
# Using KIND
kind create cluster --config=infra/kind-config.yaml --name security-platform

# Set kubectl context
kubectl cluster-info --context kind-security-platform
```

### 2. Install core infrastructure with Helm
```bash
# Add Helm repos
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana https://grafana.github.io/helm-charts
helm repo add elastic https://helm.elastic.co
helm repo add strimzi https://strimzi.io/charts/
helm repo update

# Install all components
./scripts/install-all.sh
```

### 3. Start the ML Engine
```bash
cd ml-engine
pip install -r requirements.txt
python train.py          # Train models on sample data
python serve.py          # Start inference API on :8080
```

### 4. Start microservices
```bash
cd services
docker-compose up -d
```

### 5. Access dashboards
```bash
kubectl port-forward svc/grafana 3000:3000 -n monitoring
# Open http://localhost:3000 (admin/admin)
```

---

## Project Structure

```
cloud-security-platform/
├── infra/                    # Terraform + KIND config
│   ├── main.tf               # AWS EKS, VPC, IAM
│   ├── variables.tf
│   └── kind-config.yaml      # Local dev cluster config
├── helm-charts/              # Helm deployment configs
│   ├── prometheus/
│   ├── grafana/
│   ├── kafka/
│   ├── elasticsearch/
│   └── falco/
├── ml-engine/                # AI/ML anomaly detection
│   ├── models/               # Isolation Forest + LSTM
│   ├── train.py              # Training pipeline
│   ├── serve.py              # FastAPI inference server
│   ├── evaluate.py           # Model evaluation
│   └── requirements.txt
├── services/                 # Microservices
│   ├── ingestion/            # Kafka producer / data collector
│   ├── alerting/             # Alert routing service
│   └── response-orchestrator/ # Automated playbooks
├── dashboards/               # Grafana JSON exports
├── tests/                    # Integration tests
├── scripts/                  # Helper scripts
└── docs/                     # Architecture docs
```

---

## Performance Targets

| Metric | Target |
|---|---|
| End-to-end latency | < 30 seconds (P95) |
| Log ingestion throughput | > 500,000 events/sec |
| Anomaly detection F1-score | > 92% |
| False positive rate | < 5% |
| Automated response time | < 60 seconds |
| Platform uptime SLA | 99.9% |
