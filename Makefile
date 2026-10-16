# ==============================================================================
# Makefile: Threat Detection on GCP Audit Logs with OpenSearch Security Analytics
# ==============================================================================

SHELL := /bin/bash
.DEFAULT_GOAL := help

# Load environment configuration if available
ifneq (,$(wildcard ./.env))
    include .env
    export
endif

# Fallback defaults
CONTAINER_RUNTIME ?= podman
COMPOSE_COMMAND   ?= podman-compose
OPENSEARCH_HOST   ?= http://localhost:9200
PYTHON            ?= python3

.PHONY: help quickstart setup start stop status logs health-check generate-logs ingest configure-detectors test verify cleanup clean-data

help: ## Show this help message
	@echo "================================================================================"
	@echo " Threat Detection on GCP Audit Logs with OpenSearch Security Analytics Lab"
	@echo "================================================================================"
	@echo "Available commands:"
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'

quickstart: ## Interactive, animated, all-in-one setup and verification
	@bash quickstart.sh

setup: ## Prepare local environment, configuration, and dependencies
	@echo "[+] Running environment setup..."
	@bash scripts/setup.sh

start: ## Start OpenSearch and OpenSearch Dashboards containers
	@echo "[+] Starting OpenSearch lab containers using $(COMPOSE_COMMAND)..."
	@bash scripts/start.sh

stop: ## Stop OpenSearch lab containers
	@echo "[+] Stopping OpenSearch lab containers..."
	@$(COMPOSE_COMMAND) down

status: ## Check container status
	@echo "[+] Checking container status..."
	@$(COMPOSE_COMMAND) ps

logs: ## View container logs
	@$(COMPOSE_COMMAND) logs -f

health-check: ## Verify cluster and API health
	@echo "[+] Checking service health..."
	@bash scripts/health-check.sh

generate-logs: ## Generate realistic synthetic GCP Cloud Audit Logs
	@echo "[+] Generating synthetic GCP audit events..."
	@$(PYTHON) scripts/generate-sample-logs.py

ingest: ## Ingest sample logs into OpenSearch with normalization
	@echo "[+] Ingesting sample audit logs into OpenSearch..."
	@bash scripts/ingest-sample-logs.sh

configure-detectors: ## Set up OpenSearch Security Analytics detectors and rules
	@echo "[+] Configuring Security Analytics detectors and rules..."
	@bash scripts/configure-security-analytics.sh

test: ## Run automated unit and scenario tests
	@echo "[+] Running test suite..."
	@$(PYTHON) -m pytest tests/ -v

verify: ## Run full end-to-end verification of cluster, ingestion, and findings
	@echo "[+] Running end-to-end verification..."
	@bash scripts/verify-demo.sh

clean-data: ## Delete OpenSearch test index and reset local data
	@echo "[+] Cleaning OpenSearch test index and local samples..."
	@curl -s -X DELETE "$(OPENSEARCH_HOST)/gcp-audit-logs-demo" || true
	@echo ""

cleanup: ## Safely tear down all containers, volumes, and temporary files
	@echo "[+] Tearing down lab environment..."
	@bash scripts/cleanup.sh
