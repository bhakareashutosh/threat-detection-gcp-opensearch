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

# Detect OS platform & package manager (Fedora, RHEL, Ubuntu, Debian, macOS, etc.)
DISTRO_NAME="Linux"
if [[ -f /etc/os-release ]]; then
    # shellcheck disable=SC1091
    source /etc/os-release
    DISTRO_NAME="${NAME:-${PRETTY_NAME:-Linux}}"
elif [[ "$(uname -s)" == "Darwin" ]]; then
    DISTRO_NAME="macOS"
fi

PKG_MGR=""
if command -v dnf5 &>/dev/null; then
    PKG_MGR="dnf5"
elif command -v dnf &>/dev/null; then
    PKG_MGR="dnf"
elif command -v yum &>/dev/null; then
    PKG_MGR="yum"
elif command -v apt-get &>/dev/null; then
    PKG_MGR="apt"
elif command -v brew &>/dev/null; then
    PKG_MGR="brew"
elif command -v pacman &>/dev/null; then
    PKG_MGR="pacman"
fi

echo "[*] Detected platform: ${DISTRO_NAME} ($(uname -m))"

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
    if [[ "${PKG_MGR}" == "dnf" || "${PKG_MGR}" == "dnf5" || "${PKG_MGR}" == "yum" ]]; then
        echo "    To install on Fedora / RHEL: sudo ${PKG_MGR} install -y podman podman-compose"
    elif [[ "${PKG_MGR}" == "apt" ]]; then
        echo "    To install on Ubuntu / Debian: sudo apt-get update && sudo apt-get install -y podman podman-compose"
    elif [[ "${PKG_MGR}" == "brew" ]]; then
        echo "    To install on macOS: brew install podman podman-compose"
    fi
    echo "    Please install Podman (recommended) or Docker before proceeding."
    exit 1
fi

# 3. Check Compose implementation
COMPOSE_BIN=""
if command -v podman-compose &>/dev/null; then
    COMPOSE_BIN="podman-compose"
    echo "[+] Compose tool detected: podman-compose"
elif docker compose version &>/dev/null 2>&1; then
    COMPOSE_BIN="docker compose"
    echo "[+] Compose tool detected: docker compose plugin"
elif podman compose version &>/dev/null 2>&1; then
    COMPOSE_BIN="podman compose"
    echo "[+] Compose tool detected: podman compose provider"
elif command -v docker-compose &>/dev/null; then
    COMPOSE_BIN="docker-compose"
    echo "[+] Compose tool detected: docker-compose"
else
    # Auto-install podman-compose on Fedora / RHEL / Debian if missing
    if [[ "${PKG_MGR}" == "dnf" || "${PKG_MGR}" == "dnf5" || "${PKG_MGR}" == "yum" ]]; then
        echo "[!] podman-compose missing. Attempting automatic installation via ${PKG_MGR}..."
        sudo ${PKG_MGR} install -y podman-compose 2>/dev/null || true
    elif [[ "${PKG_MGR}" == "apt" ]]; then
        echo "[!] podman-compose missing. Attempting automatic installation via apt..."
        sudo apt-get update -y 2>/dev/null && sudo apt-get install -y podman-compose 2>/dev/null || true
    fi

    if command -v podman-compose &>/dev/null; then
        COMPOSE_BIN="podman-compose"
        echo "[+] podman-compose installed successfully!"
    elif podman compose version &>/dev/null 2>&1; then
        COMPOSE_BIN="podman compose"
        echo "[+] podman compose provider available!"
    else
        echo "[-] Error: No compose tool found (podman-compose or docker-compose)."
        if [[ "${PKG_MGR}" == "dnf" || "${PKG_MGR}" == "dnf5" || "${PKG_MGR}" == "yum" ]]; then
            echo "    Fix on Fedora / RHEL: sudo ${PKG_MGR} install -y podman-compose"
        elif [[ "${PKG_MGR}" == "apt" ]]; then
            echo "    Fix on Ubuntu / Debian: sudo apt-get install -y podman-compose"
        fi
        echo "    Or install via Python pip: pip install --user podman-compose"
        exit 1
    fi
fi

# Update COMPOSE_COMMAND in .env if needed
if [[ -f "${REPO_ROOT}/.env" ]]; then
    if grep -q '^COMPOSE_COMMAND=' "${REPO_ROOT}/.env"; then
        sed -i "s|^COMPOSE_COMMAND=.*|COMPOSE_COMMAND=${COMPOSE_BIN}|" "${REPO_ROOT}/.env" 2>/dev/null || true
    fi
fi

# 4. Check Python 3
PYTHON_BIN=""
if command -v python3 &>/dev/null; then
    PYTHON_BIN="python3"
elif command -v python &>/dev/null; then
    PYTHON_BIN="python"
else
    echo "[-] Error: Python is required for test execution and log generation."
    if [[ "${PKG_MGR}" == "dnf" || "${PKG_MGR}" == "dnf5" || "${PKG_MGR}" == "yum" ]]; then
        echo "    Fix on Fedora / RHEL: sudo ${PKG_MGR} install -y python3 python3-pip"
    elif [[ "${PKG_MGR}" == "apt" ]]; then
        echo "    Fix on Ubuntu / Debian: sudo apt-get install -y python3 python3-pip"
    fi
    exit 1
fi
echo "[+] Python runtime detected: $("${PYTHON_BIN}" --version)"

# 5. Check vm.max_map_count (Linux/WSL)
if [[ "$(uname -s)" == "Linux" ]]; then
    SYSCTL_BIN=$(command -v sysctl 2>/dev/null || echo "")
    if [[ -z "${SYSCTL_BIN}" && -x /usr/sbin/sysctl ]]; then
        SYSCTL_BIN="/usr/sbin/sysctl"
    elif [[ -z "${SYSCTL_BIN}" && -x /sbin/sysctl ]]; then
        SYSCTL_BIN="/sbin/sysctl"
    fi

    MAX_MAP_COUNT=$(${SYSCTL_BIN:-sysctl} -n vm.max_map_count 2>/dev/null || cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
    if [[ "${MAX_MAP_COUNT}" -lt 262144 ]]; then
        echo "[!] Warning: vm.max_map_count is ${MAX_MAP_COUNT} (OpenSearch requires at least 262144)."
        echo "    Attempting to adjust vm.max_map_count via sudo..."
        if [[ -n "${SYSCTL_BIN}" ]]; then
            sudo "${SYSCTL_BIN}" -w vm.max_map_count=262144 2>/dev/null || true
        else
            echo 262144 | sudo tee /proc/sys/vm/max_map_count >/dev/null 2>&1 || true
        fi
        if [[ -d /etc/sysctl.d ]] && sudo -n true 2>/dev/null; then
            echo "vm.max_map_count=262144" | sudo tee /etc/sysctl.d/99-opensearch.conf >/dev/null 2>&1 || true
        fi
        NEW_MMAP=$(${SYSCTL_BIN:-sysctl} -n vm.max_map_count 2>/dev/null || cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
        if [[ "${NEW_MMAP}" -ge 262144 ]]; then
            echo "[+] Kernel vm.max_map_count successfully updated to ${NEW_MMAP}."
        else
            echo "    Run manually: sudo sysctl -w vm.max_map_count=262144"
        fi
    else
        echo "[+] Kernel vm.max_map_count is sufficient (${MAX_MAP_COUNT})."
    fi
fi

# 6. Check Rootless Podman user namespace & SELinux (Fedora / RHEL)
if [[ "${RUNTIME}" == "podman" && "$(uname -s)" == "Linux" ]]; then
    if [[ "$(id -u)" -ne 0 ]]; then
        CURRENT_USER="$(whoami 2>/dev/null || id -un 2>/dev/null || echo "")"
        if [[ -n "${CURRENT_USER}" && -f /etc/subuid ]]; then
            if ! grep -q "^${CURRENT_USER}:" /etc/subuid 2>/dev/null; then
                echo "[!] Notice: Subuid range missing for '${CURRENT_USER}'. Setting up subuid/subgid..."
                sudo usermod --add-subuids 100000-165535 --add-subgids 100000-165535 "${CURRENT_USER}" 2>/dev/null || true
            fi
        fi
    fi

    if command -v getenforce &>/dev/null; then
        SE_STATUS=$(getenforce 2>/dev/null || echo "Disabled")
        if [[ "${SE_STATUS}" == "Enforcing" ]]; then
            echo "[+] SELinux status: Enforcing (container isolation active)"
        fi
    fi
fi

# 7. Pre-generate sample datasets
echo "[+] Generating initial synthetic GCP audit datasets..."
"${PYTHON_BIN}" "${SCRIPT_DIR}/generate-sample-logs.py"

echo "================================================================================"
echo "[+] Setup completed successfully!"
echo "Next step: Start the lab environment by running:"
echo "    make start    (or: bash scripts/start.sh)"
echo "================================================================================"
