# Lab 02: Ingest and Normalize Events into OpenSearch

## Objective
In this lab, you will start the containerized OpenSearch lab environment, configure an OpenSearch Ingest Pipeline with explicit index mappings, ingest synthetic GCP Cloud Audit Logs, and verify normalized document indexing.

---

## Prerequisites
- Completed Lab 01.
- Podman (or Docker) installed and running.
- Port 9200 accessible on localhost.

---

## Key Concepts
1. **Ingest Pipeline**: A sequence of processors executed in OpenSearch before documents are indexed (e.g., date parsing, copying fields, setting taxonomy tags).
2. **Field Normalization**: Standardizing vendor-specific fields (e.g., `protoPayload.methodName`) into consistent schema targets (`event.action`, `gcp.method_name`).
3. **Idempotent Ingestion**: Using GCP's native `insertId` as the OpenSearch document `_id` prevents duplicate records when ingesting the same telemetry batch multiple times.

---

## Step-by-Step Instructions

### Step 1: Start OpenSearch
From the repository root, start the lab containers:

```bash
make start
```

Expected output:
```text
[+] Starting OpenSearch lab containers...
[*] Waiting for OpenSearch cluster to become ready at http://localhost:9200...
[+] OpenSearch is online! ("status":"green")
```

### Step 2: Check Cluster Health
Query the cluster health API:

```bash
curl -s http://localhost:9200/_cluster/health | python3 -m json.tool
```

Confirm that `"status"` is `"green"` or `"yellow"` and `"number_of_nodes"` is at least `1`.

### Step 3: Ingest Sample Logs
Run the ingestion pipeline script:

```bash
make ingest
```

Expected output:
```text
================================================================================
 GCP Cloud Audit Log Ingestion & Normalization
================================================================================
Host:       http://localhost:9200
Index:      gcp-audit-logs-demo
[+] OpenSearch cluster is accessible (status: green).
[+] Ingest pipeline 'gcp-audit-logs-normalization' configured successfully.
[+] Index 'gcp-audit-logs-demo' created with mapping and default pipeline.
[*] Reading .../sample-data/normal-events.jsonl...
[+] Successfully indexed 7 records from normal-events.jsonl.
[*] Reading .../sample-data/suspicious-events.jsonl...
[+] Successfully indexed 9 records from suspicious-events.jsonl.
--------------------------------------------------------------------------------
Summary: 16 valid records processed, 0 malformed, 16 indexed.
[+] Total verified documents in index 'gcp-audit-logs-demo': 16
================================================================================
```

### Step 4: Verify Indexed Document Count
Query the index count API:

```bash
curl -s http://localhost:9200/gcp-audit-logs-demo/_count
```

Expected result:
```json
{"count":16,"_shards":{"total":1,"successful":1,"skipped":0,"failed":0}}
```

### Step 5: Test Idempotency
Re-run `make ingest` immediately. Notice that the document count remains exactly `16` because each record updates in-place based on its unique `insertId`!

---

## Validation Steps
Retrieve an indexed document and check that normalized fields were added:

```bash
curl -s http://localhost:9200/gcp-audit-logs-demo/_doc/sim-threat-001-iam-escalation | python3 -m json.tool
```

Verify that the document contains:
- `"gcp": {"method_name": "SetIamPolicy", ...}`
- `"event": {"action": "SetIamPolicy", "outcome": "success"}`
- Full raw `"protoPayload"` preserved intact.

---

## Common Mistakes & Troubleshooting
* **`Connection refused` on port 9200**: OpenSearch takes ~30–45 seconds to boot. Wait 30 seconds and run `make health-check`.
* **Count remains 0**: Check if an error occurred during pipeline creation; review `podman logs opensearch-node`.

---

## Questions for Students
1. Why do we store both normalized fields (`gcp.method_name`) and raw fields (`protoPayload.methodName`)?
2. What would happen if we used random auto-generated document IDs instead of `insertId`?

---

## Challenge Task: Filter by High Severity

Write a curl query using OpenSearch Query DSL to return only events where `severity` is `"WARNING"` or `"CRITICAL"`.

### Hint 1:
Use a `terms` query on the `severity` field: `{"query": {"terms": {"severity": ["WARNING", "CRITICAL"]}}}`.

### Solution:
```bash
curl -s -X POST "http://localhost:9200/gcp-audit-logs-demo/_search" \
    -H "Content-Type: application/json" \
    -d '{"query": {"terms": {"severity": ["WARNING", "CRITICAL"]}}, "size": 10}' \
    | python3 -m json.tool
```
