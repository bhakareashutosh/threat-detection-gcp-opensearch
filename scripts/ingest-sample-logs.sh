#!/usr/bin/env bash
# ==============================================================================
# Ingest Sample GCP Audit Logs into OpenSearch
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

# Source .env if present
if [[ -f "${REPO_ROOT}/.env" ]]; then
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
fi

OPENSEARCH_HOST="${OPENSEARCH_HOST:-http://localhost:9200}"
INDEX_NAME="${INDEX_NAME:-gcp-audit-logs-demo}"

# Find python interpreter
PYTHON_CMD="python3"
if ! command -v python3 &>/dev/null; then
    if command -v python &>/dev/null; then
        PYTHON_CMD="python"
    else
        echo "[-] Error: Python is required to run ingestion."
        exit 1
    fi
fi

echo "[+] Launching ingestion with ${PYTHON_CMD}..."
"${PYTHON_CMD}" "${SCRIPT_DIR}/ingest_sample_logs.py" --host "${OPENSEARCH_HOST}" --index "${INDEX_NAME}"
