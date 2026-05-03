#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────
# install-all.sh — Deploy all platform components via Helm
# ─────────────────────────────────────────────────────────────────
set -euo pipefail

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; NC='\033[0m'
info()  { echo -e "${GREEN}[INFO]${NC}  $*"; }
warn()  { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error() { echo -e "${RED}[ERROR]${NC} $*" >&2; }

# ── Add Helm Repos ────────────────────────────────────────────
info "Adding Helm repositories …"
helm repo add prometheus-community https://prometheus-community.github.io/helm-charts
helm repo add grafana               https://grafana.github.io/helm-charts
helm repo add elastic               https://helm.elastic.co
helm repo add strimzi               https://strimzi.io/charts/
helm repo add falcosecurity         https://falcosecurity.github.io/charts
helm repo update
info "Helm repos updated ✓"

# ── Create Namespaces ─────────────────────────────────────────
for ns in monitoring logging kafka security; do
  kubectl get namespace "$ns" &>/dev/null || kubectl create namespace "$ns"
  info "Namespace '$ns' ready ✓"
done

# ── Prometheus + AlertManager ─────────────────────────────────
info "Installing Prometheus + AlertManager …"
helm upgrade --install kube-prometheus-stack prometheus-community/kube-prometheus-stack \
  --namespace monitoring \
  --set prometheus.prometheusSpec.retention=15d \
  --set prometheus.prometheusSpec.replicas=2 \
  --set alertmanager.enabled=true \
  --set grafana.enabled=false \
  --wait --timeout 5m
info "Prometheus installed ✓"

# ── Grafana ───────────────────────────────────────────────────
info "Installing Grafana …"
helm upgrade --install grafana grafana/grafana \
  --namespace monitoring \
  --set adminPassword=admin \
  --set persistence.enabled=true \
  --set persistence.size=5Gi \
  --set "datasources.datasources\\.yaml.apiVersion=1" \
  --set "datasources.datasources\\.yaml.datasources[0].name=Prometheus" \
  --set "datasources.datasources\\.yaml.datasources[0].type=prometheus" \
  --set "datasources.datasources\\.yaml.datasources[0].url=http://kube-prometheus-stack-prometheus:9090" \
  --set "datasources.datasources\\.yaml.datasources[0].isDefault=true" \
  --wait --timeout 3m
info "Grafana installed ✓"

# ── Kafka (via Strimzi operator) ──────────────────────────────
info "Installing Strimzi Kafka operator …"
helm upgrade --install strimzi-operator strimzi/strimzi-kafka-operator \
  --namespace kafka \
  --set watchNamespaces="{kafka}" \
  --wait --timeout 5m

info "Deploying Kafka cluster …"
kubectl apply -f - <<'EOF'
apiVersion: kafka.strimzi.io/v1beta2
kind: Kafka
metadata:
  name: security-platform
  namespace: kafka
spec:
  kafka:
    version: 3.7.0
    replicas: 3
    listeners:
      - name: plain
        port: 9092
        type: internal
        tls: false
      - name: tls
        port: 9093
        type: internal
        tls: true
    config:
      offsets.topic.replication.factor: 3
      transaction.state.log.replication.factor: 3
      transaction.state.log.min.isr: 2
      log.retention.hours: 168
      auto.create.topics.enable: "true"
    storage:
      type: jbod
      volumes:
        - id: 0
          type: persistent-claim
          size: 20Gi
          deleteClaim: false
  zookeeper:
    replicas: 3
    storage:
      type: persistent-claim
      size: 5Gi
      deleteClaim: false
  entityOperator:
    topicOperator: {}
    userOperator: {}
EOF
info "Kafka cluster deployed ✓"

# ── Elasticsearch ─────────────────────────────────────────────
info "Installing Elasticsearch …"
helm upgrade --install elasticsearch elastic/elasticsearch \
  --namespace logging \
  --set replicas=1 \
  --set resources.requests.memory=1Gi \
  --set resources.limits.memory=2Gi \
  --set esJavaOpts="-Xmx1g -Xms1g" \
  --set persistence.labels.enabled=true \
  --wait --timeout 8m
info "Elasticsearch installed ✓"

# ── Falco Runtime Security ────────────────────────────────────
info "Installing Falco …"
helm upgrade --install falco falcosecurity/falco \
  --namespace security \
  --set driver.kind=ebpf \
  --set collectors.kubernetes.enabled=true \
  --set falcosidekick.enabled=true \
  --set "falcosidekick.config.kafka.hostport=security-platform-kafka-bootstrap.kafka:9092" \
  --set "falcosidekick.config.kafka.topic=security-events-raw" \
  --wait --timeout 5m
info "Falco installed ✓"

# ── Summary ───────────────────────────────────────────────────
echo ""
info "═══════════════════════════════════════════════════════"
info "  Platform installation complete!"
info "═══════════════════════════════════════════════════════"
echo ""
info "Access Grafana:"
echo "  kubectl port-forward svc/grafana 3000:3000 -n monitoring"
echo "  → http://localhost:3000  (admin / admin)"
echo ""
info "Access Prometheus:"
echo "  kubectl port-forward svc/kube-prometheus-stack-prometheus 9090:9090 -n monitoring"
echo "  → http://localhost:9090"
echo ""
info "Access Kafka:"
echo "  kubectl get svc -n kafka"
