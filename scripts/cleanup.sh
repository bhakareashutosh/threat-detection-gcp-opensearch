#!/usr/bin/env bash
# ==============================================================================
# Cleanup Script: Safely Reset and Teardown Lab Environment
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

COMPOSE_CMD="${COMPOSE_COMMAND:-podman-compose}"
if ! command -v ${COMPOSE_CMD%% *} &>/dev/null; then
    if command -v podman-compose &>/dev/null; then
        COMPOSE_CMD="podman-compose"
    elif docker compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    elif podman compose version &>/dev/null 2>&1; then
        COMPOSE_CMD="podman compose"
    elif command -v docker-compose &>/dev/null; then
        COMPOSE_CMD="docker-compose"
    fi
fi

echo "================================================================================"
echo " Tearing down OpenSearch & GCP Threat Detection Lab"
echo "================================================================================"

# 1. Stop and remove containers and networks
if command -v ${COMPOSE_CMD%% *} &>/dev/null; then
    echo "[+] Stopping containers..."
    cd "${REPO_ROOT}"
    ${COMPOSE_CMD} down -v || true
fi

# 2. Clean temporary files and caches
echo "[+] Cleaning temporary caches..."
find "${REPO_ROOT}" -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
find "${REPO_ROOT}" -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true

echo "================================================================================"
echo "[+] Cleanup complete. Containers, networks, and lab volumes have been removed."
echo "To restart the lab fresh, run:"
echo "    make setup && make start"
echo "================================================================================"
