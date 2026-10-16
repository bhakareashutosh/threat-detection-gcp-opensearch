# Setup Guide: OpenSearch & GCP Threat Detection Lab

This guide provides end-to-end instructions for deploying, configuring, and verifying the lab environment.

---

## Quick-Start Workflow

For users with Make and Podman installed, the full workflow runs in minutes:

```bash
# 1. Clone the repository and navigate into the project directory
git clone <repository-url> threat-detection-gcp-opensearch
cd threat-detection-gcp-opensearch

# 2. Copy the environment configuration
cp .env.example .env

# 3. Run automated setup to validate dependencies
make setup

# 4. Start OpenSearch and OpenSearch Dashboards
make start

# 5. Ingest and normalize sample GCP Cloud Audit Logs
make ingest

# 6. Configure Security Analytics rules and detector
make configure-detectors

# 7. Run automated scenario verification
make verify
```

---

## Detailed Step-by-Step Instructions

### Step 1: Clone & Configure Environment

Clone the repository to your local workstation. Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Review the default parameters in `.env`:
* `OPENSEARCH_PORT=9200`: REST API port.
* `OPENSEARCH_DASHBOARDS_PORT=5601`: Web UI port.
* `INDEX_NAME=gcp-audit-logs-demo`: Target Elasticsearch/OpenSearch index for audit telemetry.
* `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g`: JVM heap memory limits (1 GB).

---

### Step 2: Validate System Requirements (`make setup`)

Run the setup validation script:

```bash
make setup
# Or execute directly:
bash scripts/setup.sh
```

This script:
1. Validates Podman or Docker availability.
2. Checks for `podman-compose` or `docker compose`.
3. Verifies Python 3 is installed.
4. Confirms that `vm.max_map_count` is at least 262144.
5. Pre-generates the synthetic normal and suspicious event files in `sample-data/`.

---

### Step 3: Launch Containers (`make start`)

Start the single-node OpenSearch 2.18.0 cluster and OpenSearch Dashboards:

```bash
make start
# Or execute directly:
bash scripts/start.sh
```

The script boots the containers in detached mode and monitors the `/_cluster/health` API endpoint until the cluster reports a ready status (`green` or `yellow`).

> [!NOTE]
> OpenSearch typically takes 30 to 60 seconds to initialize its internal plugins (Security Analytics, Alerting, k-NN, SQL).

---

### Step 4: Verify Cluster Health (`make health-check`)

Run the health check diagnostic script:

```bash
make health-check
# Or:
bash scripts/health-check.sh
```

Expected output:
* OpenSearch API: **ONLINE** (Status: yellow or green)
* Security Analytics Plugin: **ACTIVE**
* OpenSearch Dashboards: **ONLINE**

---

### Step 5: Ingest & Normalize Telemetry (`make ingest`)

Ingest the synthetic audit logs into OpenSearch:

```bash
make ingest
# Or:
bash scripts/ingest-sample-logs.sh
```

What this does:
1. Registers the Ingest Pipeline `gcp-audit-logs-normalization` in OpenSearch.
2. Creates the `gcp-audit-logs-demo` index with explicit field mappings.
3. Reads `sample-data/normal-events.jsonl` and `sample-data/suspicious-events.jsonl`.
4. Normalizes core security attributes (`event.action`, `user.name`, `source.ip`, `gcp.*`).
5. Uses the GCP `insertId` as document `_id` to ensure idempotent, duplicate-safe ingestion.
6. Verifies that all documents are indexed successfully.

---

### Step 6: Configure Security Analytics Detectors (`make configure-detectors`)

Register the Sigma detection rules and attach them to a detector:

```bash
make configure-detectors
# Or:
bash scripts/configure-security-analytics.sh
```

What this does:
1. Configures field alias mappings linking GCP audit attributes (`protoPayload.methodName`, etc.) to the Security Analytics rule schema.
2. Registers 5 custom Sigma detection rules into `_plugins/_security_analytics/rules`.
3. Creates or updates the `gcp-threat-detector` detector targeting index `gcp-audit-logs-demo` on a 1-minute evaluation schedule.

---

### Step 7: Verify Threat Detections (`make verify`)

Run the automated end-to-end verification suite:

```bash
make verify
# Or run scenario tests specifically:
make test
```

This verifies:
* Unit tests for log parsing, schema normalization, and Sigma syntax.
* Live cluster health and document count.
* Indicator telemetry for each threat scenario:
  - IAM Role Escalation (`SetIamPolicy`)
  - Service Account Key Creation (`CreateServiceAccountKey`)
  - Firewall Rule Modification (`firewalls.insert`)
  - Excessive Denied Calls (`PERMISSION_DENIED`)
  - Log Sink Deletion (`DeleteSink`)

---

### Step 8: Access OpenSearch Dashboards

Open your web browser and navigate to:
**http://localhost:5601**

1. Go to **Management > Stack Management > Index Patterns**.
2. Create an index pattern:
   - Index pattern name: `gcp-audit-logs-*`
   - Primary time field: `@timestamp`
3. Click **Discover** to explore the ingested audit logs.
4. Navigate to **OpenSearch Plugins > Security Analytics** to view the active detector, rules, and findings!
