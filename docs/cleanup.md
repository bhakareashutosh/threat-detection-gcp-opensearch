# Resource Cleanup & Environment Reset Guide

This guide details how to clean up local and cloud resources created during this lab, ensuring safe teardown and preventing unexpected cloud billing.

---

## 1. Local Simulation Teardown (Mode A)

To tear down the containerized OpenSearch lab environment:

### Automated Teardown
```bash
make cleanup
# Or execute directly:
bash scripts/cleanup.sh
```

### What `make cleanup` Does:
1. Stops and removes the `opensearch-node` and `opensearch-dashboards` containers.
2. Removes the internal bridge network (`opensearch-net`).
3. Deletes the named volume (`opensearch-data`) containing stored indices, detectors, and findings.
4. Clears Python byte-code caches (`__pycache__`) and pytest caches (`.pytest_cache`).

### Selective Reset (Keep Containers, Reset Index Data)
If you want to keep the containers running but reset the audit data and detector:
```bash
# Delete the demo index
curl -X DELETE "http://localhost:9200/gcp-audit-logs-demo"

# Re-run ingestion
make ingest
```

---

## 2. Real GCP Resource Teardown (Mode B)

If you completed the optional Mode B integration with a real Google Cloud Platform project, follow these cleanup steps to avoid recurring charges:

### Step 1: Delete Cloud Logging Sink
Deleting the sink immediately halts the export of audit events to Pub/Sub:
```bash
gcloud logging sinks delete [SINK_NAME] --project=[PROJECT_ID] --quiet
```

### Step 2: Delete Pub/Sub Subscription and Topic
```bash
# Delete the pull/push subscription
gcloud pubsub subscriptions delete [SUBSCRIPTION_NAME] --project=[PROJECT_ID] --quiet

# Delete the Pub/Sub topic
gcloud pubsub topics delete [TOPIC_NAME] --project=[PROJECT_ID] --quiet
```

### Step 3: Disable Data Access Audit Logs (If Enabled)
If you enabled billable `DATA_READ` or `DATA_WRITE` audit logging on storage buckets or other services during testing, restore default logging settings to eliminate ongoing ingestion costs:
```bash
# Revert project-level audit config to default (or remove via Terraform)
gcloud projects set-iam-policy [PROJECT_ID] policy.json
```

### Step 4: Revoke IAM Permissions and Destroy Service Account Keys
```bash
# Delete any service account keys created during exercises
gcloud iam service-accounts keys delete [KEY_ID] \
    --iam-account=[SA_NAME]@[PROJECT_ID].iam.gserviceaccount.com --quiet

# Optionally delete the lab service account
gcloud iam service-accounts delete [SA_NAME]@[PROJECT_ID].iam.gserviceaccount.com --quiet
```

### Step 5: Verify GCP Billing & Active Resources
1. In the **GCP Console**, visit **Billing > Cost Table** to confirm all charges have ceased.
2. Check **Cloud Logging > Log Router** to verify no active sinks remain.
3. Check **Pub/Sub > Topics** to confirm the topic list is clean.

---

## 3. Safe Practice Checklist for Students

Before concluding your lab session:
- [ ] Confirmed local containers stopped: `podman ps` returns empty.
- [ ] Confirmed local named volume cleaned: `podman volume ls` shows no orphaned `opensearch-data`.
- [ ] Checked `.env` file for any accidentally pasted production tokens or passwords.
- [ ] If using real GCP: Confirmed logging sinks and Pub/Sub subscriptions are deleted.
