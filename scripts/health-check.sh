#!/usr/bin/env bash
# ==============================================================================
# Health Check Script: OpenSearch Cluster, Dashboards, and Security Analytics
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_ROOT}/.env" ]]; then
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
fi

OPENSEARCH_HOST="${OPENSEARCH_HOST:-http://localhost:9200}"
OPENSEARCH_DASHBOARDS_HOST="${OPENSEARCH_DASHBOARDS_HOST:-http://localhost:5601}"
INDEX_NAME="${INDEX_NAME:-gcp-audit-logs-demo}"

echo "================================================================================"
echo " OpenSearch Lab Health Check"
echo "================================================================================"

# 1. OpenSearch Core Health
echo -n "[*] Checking OpenSearch API (${OPENSEARCH_HOST})... "
if HEALTH_RESP=$(curl -s -f "${OPENSEARCH_HOST}/_cluster/health" 2>/dev/null); then
    STATUS=$(echo "${HEALTH_RESP}" | grep -o '"status":"[^"]*"' | cut -d'"' -f4)
    NODES=$(echo "${HEALTH_RESP}" | grep -o '"number_of_nodes":[0-9]*' | cut -d':' -f2)
    echo "ONLINE (Status: ${STATUS}, Nodes: ${NODES})"
else
    echo "OFFLINE"
    echo "[-] Cannot connect to OpenSearch at ${OPENSEARCH_HOST}."
    exit 1
fi

# 2. Security Analytics Plugin Check
echo -n "[*] Checking Security Analytics plugin... "
PLUGINS=$(curl -s "${OPENSEARCH_HOST}/_cat/plugins?format=json" 2>/dev/null || echo "[]")
if echo "${PLUGINS}" | grep -q "opensearch-security-analytics"; then
    echo "ACTIVE"
else
    echo "WARNING (Plugin not found in active list)"
fi

# 3. Dashboards Health Check
echo -n "[*] Checking OpenSearch Dashboards (${OPENSEARCH_DASHBOARDS_HOST})... "
if DASH_RESP=$(curl -s -f "${OPENSEARCH_DASHBOARDS_HOST}/api/status" 2>/dev/null); then
    OVERALL=$(echo "${DASH_RESP}" | grep -o '"state":"[^"]*"' | head -n 1 | cut -d'"' -f4 || echo "ok")
    echo "ONLINE (State: ${OVERALL})"
else
    echo "INITIALIZING or OFFLINE (Dashboards may take 30-60s to boot)"
fi

# 4. Target Index Check
echo -n "[*] Checking index '${INDEX_NAME}'... "
if INDEX_EXISTS=$(curl -s -o /dev/null -w "%{http_code}" "${OPENSEARCH_HOST}/${INDEX_NAME}" 2>/dev/null); then
    if [[ "${INDEX_EXISTS}" == "200" ]]; then
        DOC_COUNT=$(curl -s "${OPENSEARCH_HOST}/${INDEX_NAME}/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d':' -f2 || echo "0")
        echo "FOUND (${DOC_COUNT} documents indexed)"
    else
        echo "NOT FOUND (Run 'make ingest' to index sample data)"
    fi
else
    echo "UNKNOWN"
fi

# 5. Security Analytics Detectors Check
echo -n "[*] Checking Security Analytics detectors... "
DETECTORS_RESP=$(curl -s -X POST "${OPENSEARCH_HOST}/_plugins/_security_analytics/detectors/_search" \
    -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' 2>/dev/null || echo "{}")
TOTAL_DETECTORS=$(echo "${DETECTORS_RESP}" | grep -o '"total":{"value":[0-9]*' | cut -d':' -f3 || echo "0")
echo "${TOTAL_DETECTORS} configured"

echo "================================================================================"
echo "[+] Health check completed."
