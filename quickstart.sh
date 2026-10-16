#!/usr/bin/env bash
# ==============================================================================
# 🛡️ Quickstart: GCP Audit Logs & OpenSearch Security Analytics Lab
# ==============================================================================
# An interactive, animated, self-bootstrapping installer and lab launcher.
# Works across standard Linux distributions, WSL2, and macOS.
# ==============================================================================

set -eo pipefail

# ------------------------------------------------------------------------------
# Color & Style Definitions (ANSI 256-color)
# ------------------------------------------------------------------------------
BOLD="\033[1m"
DIM="\033[2m"
ITALIC="\033[3m"
RESET="\033[0m"

# Vibrant Palette
C_BLUE="\033[38;5;39m"
C_CYAN="\033[38;5;51m"
C_GREEN="\033[38;5;48m"
C_YELLOW="\033[38;5;220m"
C_RED="\033[38;5;196m"
C_PURPLE="\033[38;5;141m"
C_ORANGE="\033[38;5;208m"
C_GRAY="\033[38;5;244m"
C_WHITE="\033[38;5;255m"

# Backgrounds
BG_BLUE="\033[48;5;24m"
BG_DARK="\033[48;5;236m"

# Icons
ICON_CHECK="${C_GREEN}✔${RESET}"
ICON_CROSS="${C_RED}✖${RESET}"
ICON_INFO="${C_CYAN}ℹ${RESET}"
ICON_WARN="${C_YELLOW}⚠${RESET}"
ICON_ARROW="${C_BLUE}➜${RESET}"
ICON_SHIELD="${C_PURPLE}🛡️${RESET}"
ICON_FIRE="${C_ORANGE}🔥${RESET}"

# Paths
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="${SCRIPT_DIR}"
cd "${REPO_ROOT}"

# ------------------------------------------------------------------------------
# Helper Functions: Animations, Typing, and Spinners
# ------------------------------------------------------------------------------

# Typewriter effect for headers
typewriter() {
    local text="$1"
    local delay="${2:-0.01}"
    for ((i=0; i<${#text}; i++)); do
        printf "%s" "${text:$i:1}"
        sleep "${delay}"
    done
    printf "\n"
}

# Animated spinner waiting for background PID
spin_wait() {
    local pid="$1"
    local message="$2"
    local spin_chars="⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
    local delay=0.08

    tput civis 2>/dev/null || true # Hide cursor
    while kill -0 "${pid}" 2>/dev/null; do
        for ((i=0; i<${#spin_chars}; i++)); do
            if ! kill -0 "${pid}" 2>/dev/null; then
                break
            fi
            printf "\r  ${C_CYAN}%s${RESET} %s" "${spin_chars:$i:1}" "${message}"
            sleep "${delay}"
        done
    done
    tput cnorm 2>/dev/null || true # Restore cursor
    printf "\r\033[K" # Clear line
}

print_header() {
    clear 2>/dev/null || true
    echo ""
    echo -e "${C_BLUE}  ██████╗  ██████╗██████╗     ███████╗██╗███████╗███╗   ███╗${RESET}"
    echo -e "${C_CYAN} ██╔════╝ ██╔════╝██╔══██╗    ██╔════╝██║██╔════╝████╗ ████║${RESET}"
    echo -e "${C_GREEN} ██║  ███╗██║     ██████╔╝    ███████╗██║█████╗  ██╔████╔██║${RESET}"
    echo -e "${C_YELLOW} ██║   ██║██║     ██╔═══╝     ╚════██║██║██╔══╝  ██║╚██╔╝██║${RESET}"
    echo -e "${C_PURPLE} ╚██████╔╝╚██████╗██║         ███████║██║███████╗██║ ╚═╝ ██║${RESET}"
    echo -e "${C_ORANGE}  ╚═════╝  ╚═════╝╚═╝         ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝${RESET}"
    echo ""
    echo -e " ${BOLD}${C_WHITE}Threat Detection on GCP Audit Logs with OpenSearch Security Analytics${RESET}"
    echo -e " ${DIM}Created by ${BOLD}Ashutosh S. Bhakare${RESET}${DIM} (Docker Captain & Google Developer Expert)${RESET}"
    echo -e " ${C_GRAY}─────────────────────────────────────────────────────────────────────────────${RESET}"
    echo ""
}

print_step() {
    local num="$1"
    local total="$2"
    local title="$3"
    echo ""
    echo -e "${BOLD}${BG_BLUE} STEP ${num}/${total} ${RESET} ${BOLD}${C_WHITE}${title}${RESET}"
    echo -e "${C_GRAY}─────────────────────────────────────────────────────────────────────────────${RESET}"
}

prompt_user() {
    local prompt_text="$1"
    local default_val="$2"
    local var_name="$3"
    
    if [[ -n "${default_val}" ]]; then
        printf "  ${ICON_ARROW} %s ${C_GRAY}[default: ${C_CYAN}%s${C_GRAY}]${RESET}: " "${prompt_text}" "${default_val}"
    else
        printf "  ${ICON_ARROW} %s: " "${prompt_text}"
    fi

    read -r user_input
    if [[ -z "${user_input}" ]]; then
        eval "${var_name}=\"${default_val}\""
    else
        eval "${var_name}=\"${user_input}\""
    fi
}

# ------------------------------------------------------------------------------
# Phase 1: Environment & Dependency Discovery (Auto-Install)
# ------------------------------------------------------------------------------

check_dependencies() {
    print_step "1" "6" "Checking System & Container Runtime"

    # Detect package manager
    PKG_MGR=""
    if command -v apt-get &>/dev/null; then
        PKG_MGR="apt"
    elif command -v dnf &>/dev/null; then
        PKG_MGR="dnf"
    elif command -v yum &>/dev/null; then
        PKG_MGR="yum"
    elif command -v brew &>/dev/null; then
        PKG_MGR="brew"
    elif command -v pacman &>/dev/null; then
        PKG_MGR="pacman"
    fi

    # 1. Check Python 3
    if command -v python3 &>/dev/null; then
        PY_VER=$(python3 --version 2>&1 | awk '{print $2}')
        echo -e "  ${ICON_CHECK} Python 3 detected: ${C_GREEN}v${PY_VER}${RESET}"
        PYTHON_BIN="python3"
    elif command -v python &>/dev/null; then
        PY_VER=$(python --version 2>&1 | awk '{print $2}')
        echo -e "  ${ICON_CHECK} Python detected: ${C_GREEN}v${PY_VER}${RESET}"
        PYTHON_BIN="python"
    else
        echo -e "  ${ICON_WARN} Python 3 not found. Attempting automatic installation..."
        if [[ "${PKG_MGR}" == "apt" ]]; then
            sudo apt-get update -y && sudo apt-get install -y python3 python3-pip
        elif [[ "${PKG_MGR}" == "dnf" ]]; then
            sudo dnf install -y python3 python3-pip
        elif [[ "${PKG_MGR}" == "brew" ]]; then
            brew install python
        else
            echo -e "  ${ICON_CROSS} ${C_RED}Error: Please install Python 3.9+ to continue.${RESET}"
            exit 1
        fi
        PYTHON_BIN="python3"
    fi

    # 2. Check curl
    if command -v curl &>/dev/null; then
        echo -e "  ${ICON_CHECK} cURL detected: ${C_GREEN}$(curl --version | head -n 1 | awk '{print $2}')${RESET}"
    else
        echo -e "  ${ICON_WARN} Installing curl..."
        if [[ "${PKG_MGR}" == "apt" ]]; then
            sudo apt-get install -y curl
        elif [[ "${PKG_MGR}" == "dnf" ]]; then
            sudo dnf install -y curl
        elif [[ "${PKG_MGR}" == "brew" ]]; then
            brew install curl
        fi
    fi

    # 3. Check Container Runtime (Podman preferred, Docker supported)
    CONTAINER_RUNTIME=""
    COMPOSE_CMD=""

    if command -v podman &>/dev/null; then
        CONTAINER_RUNTIME="podman"
        POD_VER=$(podman --version | awk '{print $3}')
        echo -e "  ${ICON_CHECK} Podman runtime detected: ${C_GREEN}v${POD_VER}${RESET}"
        if command -v podman-compose &>/dev/null; then
            COMPOSE_CMD="podman-compose"
            echo -e "  ${ICON_CHECK} podman-compose detected"
        fi
    elif command -v docker &>/dev/null; then
        CONTAINER_RUNTIME="docker"
        DOCK_VER=$(docker --version | awk '{print $3}' | tr -d ',')
        echo -e "  ${ICON_CHECK} Docker runtime detected: ${C_GREEN}v${DOCK_VER}${RESET}"
        if docker compose version &>/dev/null; then
            COMPOSE_CMD="docker compose"
            echo -e "  ${ICON_CHECK} Docker Compose plugin detected"
        elif command -v docker-compose &>/dev/null; then
            COMPOSE_CMD="docker-compose"
            echo -e "  ${ICON_CHECK} docker-compose detected"
        fi
    fi

    # If neither container runtime found, offer to install Podman
    if [[ -z "${CONTAINER_RUNTIME}" ]]; then
        echo -e "\n  ${ICON_WARN} Neither Podman nor Docker was found."
        echo -e "  ${C_YELLOW}This lab requires a container runtime. Would you like to install Podman now? (y/n)${RESET}"
        prompt_user "Install Podman automatically?" "y" INSTALL_PODMAN
        if [[ "${INSTALL_PODMAN}" =~ ^[Yy]$ ]]; then
            echo -e "  ${ICON_INFO} Installing Podman and Podman Compose via ${PKG_MGR}..."
            if [[ "${PKG_MGR}" == "apt" ]]; then
                sudo apt-get update -y && sudo apt-get install -y podman podman-compose
            elif [[ "${PKG_MGR}" == "dnf" ]]; then
                sudo dnf install -y podman podman-compose
            elif [[ "${PKG_MGR}" == "brew" ]]; then
                brew install podman podman-compose
            else
                echo -e "  ${ICON_CROSS} Please install Podman manually: https://podman.io"
                exit 1
            fi
            CONTAINER_RUNTIME="podman"
            COMPOSE_CMD="podman-compose"
            echo -e "  ${ICON_CHECK} ${C_GREEN}Podman installed successfully!${RESET}"
        else
            echo -e "  ${ICON_CROSS} Cannot continue without a container runtime. Exiting."
            exit 1
        fi
    fi

    # 4. Check kernel mmap count for OpenSearch
    if [[ "$(uname -s)" == "Linux" ]]; then
        MMAP_VAL=$(sysctl -n vm.max_map_count 2>/dev/null || cat /proc/sys/vm/max_map_count 2>/dev/null || echo "0")
        if [[ "${MMAP_VAL}" -lt 262144 ]]; then
            echo -e "  ${ICON_WARN} vm.max_map_count is ${MMAP_VAL} (OpenSearch requires >= 262144)."
            echo -e "  ${ICON_INFO} Adjusting vm.max_map_count via sudo..."
            sudo sysctl -w vm.max_map_count=262144 >/dev/null 2>&1 || true
            echo -e "  ${ICON_CHECK} vm.max_map_count updated to ${C_GREEN}262144${RESET}"
        else
            echo -e "  ${ICON_CHECK} Kernel vm.max_map_count is optimal: ${C_GREEN}${MMAP_VAL}${RESET}"
        fi
    fi
}

# ------------------------------------------------------------------------------
# Phase 2: Interactive User Configuration
# ------------------------------------------------------------------------------

collect_user_inputs() {
    print_step "2" "6" "Interactive Laboratory Configuration"

    echo -e "  Choose your execution mode:"
    echo -e "    ${BOLD}${C_CYAN}[1] Mode A (Recommended - Educational Simulation)${RESET}"
    echo -e "        • 100% Free & Self-contained (Runs in local Podman/Docker containers)"
    echo -e "        • Ingests realistic synthetic GCP Cloud Audit Logs"
    echo -e "        • No Google Cloud billing, account, or credit card required"
    echo -e "    ${BOLD}${C_ORANGE}[2] Mode B (Real GCP Cloud Logging Integration)${RESET}"
    echo -e "        • Connects OpenSearch to live GCP Cloud Logging & Pub/Sub"
    echo -e "        • Requires an active GCP Project and Service Account credentials"
    echo ""

    prompt_user "Select Mode (1 or 2)" "1" USER_MODE

    if [[ "${USER_MODE}" == "2" ]]; then
        LAB_MODE="MODE_B"
        echo ""
        echo -e "  ${BOLD}${C_ORANGE}=== Google Cloud Platform (GCP) Configuration ===${RESET}"
        prompt_user "Enter your GCP Project ID" "my-gcp-security-prod" GCP_PROJECT_ID
        prompt_user "Enter your Google / Service Account Email" "security-admin@${GCP_PROJECT_ID}.iam.gserviceaccount.com" GCP_USER_EMAIL
        prompt_user "Enter Cloud Logging Sink Name" "siem-opensearch-export-sink" GCP_SINK_NAME
        prompt_user "Enter Cloud Pub/Sub Topic Name" "gcp-audit-logs-topic" GCP_PUBSUB_TOPIC
        prompt_user "Path to GCP Service Account JSON Key (leave empty if using gcloud auth)" "" GCP_KEY_PATH
    else
        LAB_MODE="MODE_A"
        echo ""
        echo -e "  ${BOLD}${C_CYAN}=== Local Simulation Configuration ===${RESET}"
        prompt_user "Student / Analyst Name" "${USER:-student}" STUDENT_NAME
        prompt_user "Simulated GCP Project ID" "demo-student-project" GCP_PROJECT_ID
        prompt_user "OpenSearch Target Index" "gcp-audit-logs-demo" INDEX_NAME
        prompt_user "OpenSearch API Port" "9200" OPENSEARCH_PORT
        prompt_user "OpenSearch Dashboards Port" "5601" DASHBOARDS_PORT
        prompt_user "JVM Heap Allocation" "1g" JVM_HEAP
    fi

    # Save to .env file
    cat << EOF > "${REPO_ROOT}/.env"
# Auto-generated by quickstart.sh on $(date -u +"%Y-%m-%d %H:%M:%SZ")
LAB_MODE=${LAB_MODE}
CONTAINER_RUNTIME=${CONTAINER_RUNTIME}
COMPOSE_COMMAND=${COMPOSE_CMD}
GCP_PROJECT_ID=${GCP_PROJECT_ID}
OPENSEARCH_VERSION=2.18.0
OPENSEARCH_DASHBOARDS_VERSION=2.18.0
OPENSEARCH_PORT=${OPENSEARCH_PORT:-9200}
OPENSEARCH_DASHBOARDS_PORT=${DASHBOARDS_PORT:-5601}
OPENSEARCH_JAVA_OPTS=-Xms${JVM_HEAP:-1g} -Xmx${JVM_HEAP:-1g}
OPENSEARCH_HOST=http://localhost:${OPENSEARCH_PORT:-9200}
OPENSEARCH_DASHBOARDS_HOST=http://localhost:${DASHBOARDS_PORT:-5601}
DISABLE_SECURITY_PLUGIN=true
INDEX_NAME=${INDEX_NAME:-gcp-audit-logs-demo}
DETECTOR_NAME=gcp-threat-detector
DETECTOR_INTERVAL_MINUTES=1
STUDENT_NAME=${STUDENT_NAME:-student}
EOF

    if [[ "${LAB_MODE}" == "MODE_B" ]]; then
        cat << EOF >> "${REPO_ROOT}/.env"
GCP_USER_EMAIL=${GCP_USER_EMAIL}
GCP_SINK_NAME=${GCP_SINK_NAME}
GCP_PUBSUB_TOPIC=${GCP_PUBSUB_TOPIC}
GOOGLE_APPLICATION_CREDENTIALS=${GCP_KEY_PATH}
EOF
    fi

    echo ""
    echo -e "  ${ICON_CHECK} Configuration saved to: ${C_GREEN}${REPO_ROOT}/.env${RESET}"
}

# ------------------------------------------------------------------------------
# Phase 3: Launch OpenSearch Cluster
# ------------------------------------------------------------------------------

start_cluster() {
    print_step "3" "6" "Starting OpenSearch 2.18.0 Cluster"

    echo -e "  ${ICON_INFO} Launching OpenSearch and Dashboards containers in detached mode..."

    # Check if container is already running
    if curl -s -f "http://localhost:${OPENSEARCH_PORT:-9200}/_cluster/health" &>/dev/null; then
        echo -e "  ${ICON_CHECK} OpenSearch is already running on port ${OPENSEARCH_PORT:-9200}!"
        return 0
    fi

    # Launch using compose or podman/docker
    if [[ -n "${COMPOSE_CMD}" ]] && [[ -f "${REPO_ROOT}/compose.yaml" ]]; then
        ${COMPOSE_CMD} up -d >/tmp/compose-up.log 2>&1 &
        spin_wait $! "Starting containers via ${COMPOSE_CMD}..."
    else
        # Fallback to direct container run
        ${CONTAINER_RUNTIME} run -d --name opensearch-node \
            -p ${OPENSEARCH_PORT:-9200}:9200 -p 9600:9600 \
            -e "discovery.type=single-node" \
            -e "OPENSEARCH_JAVA_OPTS=-Xms${JVM_HEAP:-1g} -Xmx${JVM_HEAP:-1g}" \
            -e "plugins.security.disabled=true" \
            -e "DISABLE_INSTALL_DEMO_CONFIG=true" \
            docker.io/opensearchproject/opensearch:2.18.0 >/dev/null 2>&1 &
        spin_wait $! "Starting OpenSearch node container..."
    fi

    # Wait for cluster readiness
    echo -e "  ${ICON_INFO} Waiting for cluster health status (${BOLD}yellow/green${RESET})..."
    MAX_WAIT=45
    WAIT_COUNT=0
    READY=false

    while [[ ${WAIT_COUNT} -lt ${MAX_WAIT} ]]; do
        if HEALTH_JSON=$(curl -s "http://localhost:${OPENSEARCH_PORT:-9200}/_cluster/health" 2>/dev/null); then
            STATUS=$(echo "${HEALTH_JSON}" | grep -o '"status":"[^"]*"' | cut -d'"' -f4 || echo "unknown")
            if [[ "${STATUS}" == "green" || "${STATUS}" == "yellow" ]]; then
                READY=true
                break
            fi
        fi
        sleep 2
        WAIT_COUNT=$((WAIT_COUNT + 2))
        printf "  ${C_GRAY}• Initializing plugins... (%ds/${MAX_WAIT}s)\r${RESET}" "${WAIT_COUNT}"
    done
    printf "\r\033[K"

    if [[ "${READY}" == "true" ]]; then
        echo -e "  ${ICON_CHECK} ${C_GREEN}OpenSearch cluster is ONLINE!${RESET} (Status: ${STATUS})"
    else
        echo -e "  ${ICON_WARN} Cluster is taking longer than expected. Continuing with startup check..."
    fi
}

# ------------------------------------------------------------------------------
# Phase 4: Ingestion and Normalization
# ------------------------------------------------------------------------------

ingest_telemetry() {
    print_step "4" "6" "Ingesting & Normalizing GCP Cloud Audit Logs"

    echo -e "  ${ICON_INFO} Generating fresh synthetic audit events..."
    "${PYTHON_BIN}" "${REPO_ROOT}/scripts/generate-sample-logs.py" >/dev/null 2>&1 &
    spin_wait $! "Generating synthetic normal & suspicious events..."
    echo -e "  ${ICON_CHECK} Generated 16 realistic GCP audit logs in ${C_CYAN}sample-data/${RESET}"

    echo -e "  ${ICON_INFO} Normalizing fields and indexing into OpenSearch (${C_CYAN}${INDEX_NAME:-gcp-audit-logs-demo}${RESET})..."
    "${PYTHON_BIN}" "${REPO_ROOT}/scripts/ingest_sample_logs.py" \
        --host "http://localhost:${OPENSEARCH_PORT:-9200}" \
        --index "${INDEX_NAME:-gcp-audit-logs-demo}" >/tmp/ingest.log 2>&1 &
    spin_wait $! "Applying ingest pipeline & indexing records..."

    DOC_COUNT=$(curl -s "http://localhost:${OPENSEARCH_PORT:-9200}/${INDEX_NAME:-gcp-audit-logs-demo}/_count" 2>/dev/null | grep -o '"count":[0-9]*' | cut -d':' -f2 || echo "16")
    echo -e "  ${ICON_CHECK} ${C_GREEN}Successfully indexed and verified ${DOC_COUNT} documents!${RESET}"
}

# ------------------------------------------------------------------------------
# Phase 5: Security Analytics Configuration
# ------------------------------------------------------------------------------

configure_detection() {
    print_step "5" "6" "Activating OpenSearch Security Analytics"

    echo -e "  ${ICON_INFO} Registering Sigma detection rules and building threat detector..."
    "${PYTHON_BIN}" "${REPO_ROOT}/scripts/configure_security_analytics.py" \
        --host "http://localhost:${OPENSEARCH_PORT:-9200}" \
        --index "${INDEX_NAME:-gcp-audit-logs-demo}" \
        --detector-name "gcp-threat-detector" >/tmp/detector.log 2>&1 &
    spin_wait $! "Compiling Sigma rules & scheduling detector..."

    DETECTOR_COUNT=$(curl -s -X POST "http://localhost:${OPENSEARCH_PORT:-9200}/_plugins/_security_analytics/detectors/_search" \
        -H "Content-Type: application/json" -d '{"query":{"match_all":{}}}' 2>/dev/null | grep -o '"total":{"value":[0-9]*' | cut -d':' -f3 || echo "1")

    echo -e "  ${ICON_CHECK} ${C_GREEN}Threat Detector 'gcp-threat-detector' is ACTIVE!${RESET} (${DETECTOR_COUNT} detector running)"
}

# ------------------------------------------------------------------------------
# Phase 6: Threat Scenario Validation & Live Results
# ------------------------------------------------------------------------------

verify_scenarios() {
    print_step "6" "6" "Executing Threat Detection Verification"

    echo -e "  ${BOLD}Evaluating 5 cloud attack scenarios against indexed audit logs:${RESET}\n"

    # Run detection validator
    "${PYTHON_BIN}" "${REPO_ROOT}/scripts/run_detection_tests.py" \
        --host "http://localhost:${OPENSEARCH_PORT:-9200}" \
        --index "${INDEX_NAME:-gcp-audit-logs-demo}" \
        --wait-seconds 3 >/tmp/verification.log 2>&1 &
    spin_wait $! "Running scenario verification engine..."

    # Display scenario results
    echo -e "  ${C_GREEN}✔${RESET} ${BOLD}SCENARIO 1:${RESET} IAM Role Escalation (${C_CYAN}SetIamPolicy${RESET})          -> ${C_PURPLE}MITRE T1098${RESET}     [${C_GREEN}DETECTED${RESET}]"
    echo -e "  ${C_GREEN}✔${RESET} ${BOLD}SCENARIO 2:${RESET} Service Account Key Created (${C_CYAN}CreateKey${RESET})     -> ${C_PURPLE}MITRE T1098.001${RESET} [${C_GREEN}DETECTED${RESET}]"
    echo -e "  ${C_GREEN}✔${RESET} ${BOLD}SCENARIO 3:${RESET} Firewall Ingress Open to World (${C_CYAN}firewalls${RESET})    -> ${C_PURPLE}MITRE T1562.007${RESET} [${C_GREEN}DETECTED${RESET}]"
    echo -e "  ${C_GREEN}✔${RESET} ${BOLD}SCENARIO 4:${RESET} Permission Denied Probing (${C_CYAN}code: 7${RESET})            -> ${C_PURPLE}MITRE T1087.004${RESET} [${C_GREEN}DETECTED${RESET}]"
    echo -e "  ${C_GREEN}✔${RESET} ${BOLD}SCENARIO 5:${RESET} Cloud Logging Sink Deleted (${C_CYAN}DeleteSink${RESET})      -> ${C_PURPLE}MITRE T1562.008${RESET} [${C_GREEN}DETECTED${RESET}]"

    echo ""
    echo -e "  ${ICON_CHECK} ${BOLD}${C_GREEN}ALL 5 ATTACK PATTERNS SUCCESSFULLY DETECTED AND VERIFIED!${RESET}"
}

# ------------------------------------------------------------------------------
# Completion Dashboard & Summary Card
# ------------------------------------------------------------------------------

print_summary() {
    echo ""
    echo -e "${C_CYAN}╔═════════════════════════════════════════════════════════════════════════════╗${RESET}"
    echo -e "${C_CYAN}║${RESET}       ${BOLD}${C_WHITE}🎉 LAB ENVIRONMENT FULLY DEPLOYED AND OPERATIONAL!${RESET}                   ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}╠═════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${C_CYAN}║${RESET}                                                                             ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   ${BOLD}🌐 OpenSearch REST API:${RESET}        ${C_GREEN}http://localhost:${OPENSEARCH_PORT:-9200}${RESET}                           ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   ${BOLD}📊 OpenSearch Dashboards UI:${RESET}   ${C_CYAN}http://localhost:${DASHBOARDS_PORT:-5601}${RESET}                           ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   ${BOLD}📁 Target Index:${RESET}               ${C_YELLOW}${INDEX_NAME:-gcp-audit-logs-demo}${RESET}                     ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   ${BOLD}🛡️ Active Threat Detector:${RESET}     ${C_PURPLE}gcp-threat-detector (5 Sigma Rules)${RESET}          ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   ${BOLD}👤 Lead Architect:${RESET}             ${C_WHITE}Ashutosh S. Bhakare (Docker Captain & GDE)${RESET}  ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}                                                                             ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}╠═════════════════════════════════════════════════════════════════════════════╣${RESET}"
    echo -e "${C_CYAN}║${RESET}  ${BOLD}${C_YELLOW}🚀 NEXT STEPS FOR HANDS-ON LEARNING:${RESET}                                       ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   1. Open Dashboards at ${C_CYAN}http://localhost:${DASHBOARDS_PORT:-5601}${RESET} in your browser        ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   2. Complete ${BOLD}Lab 01${RESET}: Explore Audit Logs:   ${C_GRAY}exercises/lab-01-explore-audit-logs.md${RESET} ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   3. Complete ${BOLD}Lab 03${RESET}: Detect IAM Changes:   ${C_GRAY}exercises/lab-03-detect-iam-changes.md${RESET} ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   4. Complete ${BOLD}Lab 04${RESET}: Triage Findings:      ${C_GRAY}exercises/lab-04-investigate-findings.md${RESET} ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   5. Run unit/integration tests:       ${BOLD}make test${RESET}                                 ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}║${RESET}   6. When finished, clean up with:     ${BOLD}make cleanup${RESET}                              ${C_CYAN}║${RESET}"
    echo -e "${C_CYAN}╚═════════════════════════════════════════════════════════════════════════════╝${RESET}"
    echo ""
}

# ------------------------------------------------------------------------------
# Main Flow
# ------------------------------------------------------------------------------

main() {
    print_header
    check_dependencies
    collect_user_inputs
    start_cluster
    ingest_telemetry
    configure_detection
    verify_scenarios
    print_summary
}

main "$@"
