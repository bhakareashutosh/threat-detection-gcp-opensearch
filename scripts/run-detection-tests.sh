#!/usr/bin/env bash
# ==============================================================================
# Run Detection Scenario Tests
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

if [[ -f "${REPO_ROOT}/.env" ]]; then
    # Auto-repair unquoted OPENSEARCH_JAVA_OPTS if present
    if grep -q '^OPENSEARCH_JAVA_OPTS=[^"].*[[:space:]]' "${REPO_ROOT}/.env"; then
        sed -i 's/^OPENSEARCH_JAVA_OPTS=\(.*\)$/OPENSEARCH_JAVA_OPTS="\1"/' "${REPO_ROOT}/.env" 2>/dev/null || true
    fi
    # shellcheck disable=SC1091
    source "${REPO_ROOT}/.env"
fi

OPENSEARCH_HOST="${OPENSEARCH_HOST:-http://localhost:9200}"
INDEX_NAME="${INDEX_NAME:-gcp-audit-logs-demo}"
DETECTOR_NAME="${DETECTOR_NAME:-gcp-threat-detector}"

PYTHON_CMD="python3"
if ! command -v python3 &>/dev/null; then
    if command -v python &>/dev/null; then
        PYTHON_CMD="python"
    else
        echo "[-] Error: Python is required."
        exit 1
    fi
fi

"${PYTHON_CMD}" "${SCRIPT_DIR}/run_detection_tests.py" \
    --host "${OPENSEARCH_HOST}" \
    --index "${INDEX_NAME}" \
    --detector-name "${DETECTOR_NAME}" \
    --wait-seconds 10
