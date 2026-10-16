# Lab 05: Build a Custom Detection Rule

## Objective
In this lab, you will act as a Detection Engineer. You will author a new custom Sigma detection rule for an emerging cloud threat, create a corresponding synthetic test audit event, register the rule in OpenSearch Security Analytics, and validate the detection using automated tests.

---

## Prerequisites
- Completed Labs 01 through 04.
- Basic understanding of Sigma YAML/JSON syntax.
- Working OpenSearch cluster (`make health-check`).

---

## Threat Scenario: Cloud Storage Bucket ACL Public Exposure

### The Threat
Adversaries or careless developers frequently modify Cloud Storage bucket permissions (`storage.setIamPermissions`) to make buckets publicly readable to `allUsers` or `allAuthenticatedUsers`. This exposes confidential company documents, database backups, or intellectual property directly to the internet.

### Targeted Telemetry Attributes
* `protoPayload.serviceName`: `storage.googleapis.com`
* `protoPayload.methodName`: `storage.setIamPermissions`
* MITRE ATT&CK: **T1530 — Data from Cloud Storage Object**
* Severity: **High**

---

## Step-by-Step Instructions

### Step 1: Create the Detection Rule File
Create a new rule file named `detection-rules/custom-rules/gcp_storage_bucket_iam_changed.json`:

```json
{
  "title": "GCP Cloud Storage Bucket IAM Policy Modified",
  "id": "b2c3d4e5-f6a1-4b2c-8d3e-4f5a6b7c8d99",
  "description": "Detects changes to Google Cloud Storage bucket IAM access policies (storage.setIamPermissions), potentially exposing bucket data publicly.",
  "status": "experimental",
  "author": "Student Detection Engineer",
  "date": "2026/10/16",
  "references": [
    "https://cloud.google.com/storage/docs/access-control/iam",
    "https://attack.mitre.org/techniques/T1530/"
  ],
  "tags": [
    "attack.collection",
    "attack.t1530"
  ],
  "logsource": {
    "product": "others_application",
    "service": "gcp_audit"
  },
  "detection": {
    "selection": {
      "gcp.method_name": "storage.setIamPermissions"
    },
    "condition": "selection"
  },
  "level": "high",
  "falsepositives": [
    "Intentional public asset hosting for static websites",
    "Automated bucket provisioning scripts"
  ]
}
```

Save this file in `detection-rules/custom-rules/gcp_storage_bucket_iam_changed.json`.

### Step 2: Append a Synthetic Test Event
Append a simulated bucket IAM modification event to `sample-data/suspicious-events.jsonl`:

```bash
cat << 'EOF' >> sample-data/suspicious-events.jsonl
{"insertId":"sim-threat-006-storage-exposed","logName":"projects/demo-student-project/logs/cloudaudit.googleapis.com%2Factivity","timestamp":"2026-10-16T12:45:00Z","severity":"WARNING","resource":{"type":"gcs_bucket","labels":{"project_id":"demo-student-project"}},"protoPayload":{"@type":"type.googleapis.com/google.cloud.audit.AuditLog","serviceName":"storage.googleapis.com","methodName":"storage.setIamPermissions","resourceName":"projects/_/buckets/confidential-customer-backups","authenticationInfo":{"principalEmail":"rogue-contractor@demo-corp.internal","callerIp":"198.51.100.99"},"requestMetadata":{"callerIp":"198.51.100.99"},"status":{"code":0,"message":""}},"threatContext":{"scenario":"Storage Bucket IAM Public Exposure","mitre_technique":"T1530"}}
EOF
```

### Step 3: Ingest the New Telemetry
Run the ingestion script to index the new event:

```bash
make ingest
```

Verify that document count increased:
```bash
curl -s http://localhost:9200/gcp-audit-logs-demo/_count
```

### Step 4: Register the Custom Rule
Upload the new rule into Security Analytics:

```bash
make configure-detectors
```

Verify that the rule is registered:
```text
[+] Created rule: 'GCP Cloud Storage Bucket IAM Policy Modified'
```

### Step 5: Verify the Rule Matches the Telemetry
Query OpenSearch to confirm the indicator matches:

```bash
curl -s -X POST "http://localhost:9200/gcp-audit-logs-demo/_search" \
    -H "Content-Type: application/json" \
    -d '{
      "query": {
        "term": { "gcp.method_name": "storage.setIamPermissions" }
      }
    }' | python3 -m json.tool
```

Verify that `sim-threat-006-storage-exposed` is returned in hits!

---

## Validation Steps
Run the test suite to ensure no regressions occurred:

```bash
make test
```

All unit and integration tests must pass.

---

## Questions for Students
1. How could you refine this rule to alert only when `allUsers` or `allAuthenticatedUsers` is present in the policy binding?
2. What organization policy constraint in GCP prevents public bucket exposure organization-wide?

---

## Challenge Task: Add a False Positive Filter

Modify your Sigma rule to ignore events where `protoPayload.authenticationInfo.principalEmail` is `terraform-sa@demo-student-project.iam.gserviceaccount.com`.

### Hint 1:
In Sigma syntax, create two selections: `selection` (method matching) and `filter` (principal matching), with `condition: selection and not filter`.

### Solution:
```json
{
  "detection": {
    "selection": {
      "gcp.method_name": "storage.setIamPermissions"
    },
    "filter": {
      "gcp.principal": "terraform-sa@demo-student-project.iam.gserviceaccount.com"
    },
    "condition": "selection and not filter"
  }
}
```
