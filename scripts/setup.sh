#!/usr/bin/env bash
# ==============================================================================
# Setup Script: Threat Detection on GCP Audit Logs with OpenSearch
# ==============================================================================
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

echo "================================================================================"
echo " Setting up OpenSearch & GCP Threat Detection Lab"
echo "================================================================================"

# 1. Initialize .env from template if missing
if [[ ! -f "${REPO_ROOT}/.env" ]]; then
    echo "[+] Creating .env configuration from template..."
    cp "${REPO_ROOT}/.env.example" "${REPO_ROOT}/.env"
    echo "    Created: ${REPO_ROOT}/.env"
else
    echo "[*] Existing .env found."
fi

# 2. Check Container Runtime (Podman preferred, Docker supported)
RUNTIME=""
if command -v podman &>/dev/null; then
    RUNTIME="podman"
    echo "[+] Container runtime detected: Podman ($(podman --version))"
elif command -v docker &>/dev/null; then
    RUNTIME="docker"
    echo "[+] Container runtime detected: Docker ($(docker --version))"
else
    echo "[-] Error: Neither Podman nor Docker was found in your PATH."
    echo "    Please install Podman (recommended) or Docker before proceeding."
    exit 1
fi

# 3. Check Compose implementation
COMPOSE_BIN=""
if command -v podman-compose &>/dev/null; then
    COMPOSE_BIN="podman-compose"
    echo "[+] Compose tool detected: podman-compose"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_BIN="docker-compose"
    echo "[+] Compose tool detected: docker-compose"
elif docker compose version &>/dev/null; then
    COMPOSE_BIN="docker compose"
    echo "[+] Compose tool detected: docker compose plugin"
else
    echo "[-] Error: No compose tool found (podman-compose or docker-compose)."
    exit 1
fi

# 4. Check Python 3
PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo "[-] Error: Python is required for test execution and log generation."
    exit 1
fi
echo "[+] Python runtime detected: $("${PYTHON_BIN}" --version)"

# 5. Check vm.max_map_count (Linux/WSL)
if [[ "$(uname -s)" == "Linux" ]]; then
    MAX_MAP_COUNT=$(sysctl -n vm.max_map_count 2>/dev/null || cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
    if [[ "${MAX_MAP_COUNT}" -lt 262144 ]]; then
        echo "[!] Warning: vm.max_map_count is ${MAX_MAP_COUNT} (OpenSearch requires at least 262144)."
        echo "    Run: sudo sysctl -w vm.max_map_count=262144"
    else
        echo "[+] Kernel vm.max_map_count is sufficient (${MAX_MAP_COUNT})."
    fi
fi

# 6. Pre-generate sample datasets
echo "[+] Generating initial synthetic GCP audit datasets..."
"${PYTHON_BIN}" "${SCRIPT_DIR}/generate-sample-logs.py"

echo "================================================================================"
echo "[+] Setup completed successfully!"
echo "Next step: Start the lab environment by running:"
echo "    make start    (or: bash scripts/start.sh)"
echo "================================================================================"
