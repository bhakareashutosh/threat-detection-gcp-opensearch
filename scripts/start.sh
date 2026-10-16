#!/usr/bin/env bash
# ==============================================================================
# Start Script: Launch OpenSearch and Dashboards Lab
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source .env if present
if [[ -f "${REPO_ROOT}/.env" ]]; then
    # Auto-repair unquoted OPENSEARCH_JAVA_OPTS if present
    if grep -q '^OPENSEARCH_JAVA_OPTS=[^"].*[[:space:]]' "${REPO_ROOT}/.env"; then
        sed -i 's/^OPENSEARCH_JAVA_OPTS=\(.*\)$/OPENSEARCH_JAVA_OPTS="\1"/' "${REPO_ROOT}/.env" 2>/dev/null || true
    fi
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
fi

OPENSEARCH_HOST="${OPENSEARCH_HOST:-http://localhost:9200}"
OPENSEARCH_DASHBOARDS_HOST="${OPENSEARCH_DASHBOARDS_HOST:-http://localhost:5601}"
COMPOSE_CMD="${COMPOSE_COMMAND:-podman-compose}"

# Fallback detection for compose command
if ! command -v ${COMPOSE_CMD%% *} &>/dev/null; then
    if command -v podman-compose &>/dev/null; then
        COMPOSE_CMD="podman-compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    elif docker compose version &>/dev/null; then
        COMPOSE_CMD="docker compose"
    else
        echo "[-] Error: No working compose command found."
        exit 1
    fi
fi

echo "================================================================================"
echo " Starting OpenSearch & OpenSearch Dashboards with ${COMPOSE_CMD}..."
echo "================================================================================"

cd "${REPO_ROOT}"
${COMPOSE_CMD} up -d

echo "[*] Waiting for OpenSearch cluster to become ready at ${OPENSEARCH_HOST}..."
MAX_ATTEMPTS=40
ATTEMPT=1
READY=false

while [[ ${ATTEMPT} -le ${MAX_ATTEMPTS} ]]; do
    if curl -s -f "${OPENSEARCH_HOST}/_cluster/health" &>/dev/null; then
        READY=true
        break
    fi
    printf "."
    sleep 3
    ATTEMPT=$((ATTEMPT + 1))
done
echo ""

if [[ "${READY}" == "true" ]]; then
    CLUSTER_HEALTH=$(curl -s "${OPENSEARCH_HOST}/_cluster/health" | grep -o '"status":"[^"]*"' || echo "status: unknown")
    echo "[+] OpenSearch is online! (${CLUSTER_HEALTH})"
    echo ""
    echo "================================================================================"
    echo " Access Endpoints:"
    echo "   - OpenSearch API:        ${OPENSEARCH_HOST}"
    echo "   - OpenSearch Dashboards: ${OPENSEARCH_DASHBOARDS_HOST}"
    echo "   - Cluster Health:        ${OPENSEARCH_HOST}/_cluster/health"
    echo "================================================================================"
    echo "Next steps:"
    echo "   1. Run 'make health-check' to verify all components"
    echo "   2. Run 'make ingest' to index sample audit logs"
    echo "   3. Run 'make configure-detectors' to activate threat detectors"
else
    echo "[-] OpenSearch failed to respond within $((MAX_ATTEMPTS * 3)) seconds."
    echo "    Check container logs using: ${COMPOSE_CMD} logs opensearch"
    exit 1
fi
