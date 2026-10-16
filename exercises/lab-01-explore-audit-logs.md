# Lab 01: Explore GCP Cloud Audit Logs

## Objective
In this lab, you will inspect raw Google Cloud Platform (GCP) Cloud Audit Logs in JSON Lines (`.jsonl`) format. By the end of this exercise, you will understand how to identify the actor, the operation performed, the target resource, the network origin, and whether the API call succeeded or was denied.

---

## Prerequisites
- Completed repository setup (`make setup`).
- A command-line terminal with Python 3, `cat`, `grep`, and `jq` (or Python's built-in `json.tool`).

---

## Key Concepts

Every GCP Cloud Audit Log uses a Google Protobuf format containing three main sections:
1. **Top-Level Envelope**: Contains `timestamp`, `logName`, `insertId`, and `severity`.
2. **Resource Block (`resource`)**: Identifies the GCP service category (`project`, `gce_instance`, `gcs_bucket`) and identifiers.
3. **Payload (`protoPayload`)**: Contains the core audit telemetry:
   - `authenticationInfo.principalEmail`: Who ran the command?
   - `methodName`: What API method was invoked?
   - `requestMetadata.callerIp`: From what IP address?
   - `status.code`: Did it succeed (0) or fail (>0)?

---

## Step-by-Step Instructions

### Step 1: Inspect Sample Log Files
Navigate to the sample data directory:
```bash
cd sample-data
ls -la
```

Expected output:
```text
normal-events.jsonl
suspicious-events.jsonl
README.md
```

### Step 2: Pretty-Print a Benign Event
View the first record in `normal-events.jsonl` formatted as JSON:

```bash
head -n 1 normal-events.jsonl | python3 -m json.tool
```

Expected output (snippet):
```json
{
    "insertId": "sim-norm-...",
    "logName": "projects/demo-student-project/logs/cloudaudit.googleapis.com%2Fdata_access",
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "authenticationInfo": {
            "principalEmail": "devops-engineer@demo-corp.internal"
        },
        "methodName": "v1.compute.instances.list",
        "serviceName": "compute.googleapis.com",
        "status": {
            "code": 0,
            "message": ""
        }
    },
    "severity": "INFO",
    "timestamp": "..."
}
```

### Step 3: Identify a Suspicious Privilege Escalation Event
Search for IAM policy changes in `suspicious-events.jsonl`:

```bash
grep "SetIamPolicy" suspicious-events.jsonl | python3 -m json.tool
```

Notice:
1. `methodName`: `"SetIamPolicy"`
2. `serviceData.policyDelta.bindingDeltas`:
   - Role added: `roles/owner`
   - Member added: `user:attacker-exfil@external-mail.example`

### Step 4: Examine a Denied Operation
Search for unauthorized operations:

```bash
grep '"code": 7' suspicious-events.jsonl | head -n 1 | python3 -m json.tool
```

Notice that `code: 7` corresponds to Google RPC `PERMISSION_DENIED`.

---

## Validation Steps
Confirm you can answer these three questions using command-line filters:
1. What IP address did the attacker use in `sim-threat-001-iam-escalation`?
   ```bash
   grep "sim-threat-001" suspicious-events.jsonl | python3 -c "import sys, json; print(json.load(sys.stdin)['protoPayload']['requestMetadata']['callerIp'])"
   ```
   *Expected Output*: `198.51.100.45`

---

## Common Mistakes & Troubleshooting
* **Error `python3: command not found`**: On Windows, use `python` or ensure Python is added to your system PATH.
* **JSON decode error**: Verify you only piped a single line (using `head -n 1`), not multiple JSONL lines at once into `json.tool`.

---

## Questions for Students
1. Why is `SetIamPolicy` considered an **Admin Activity** log rather than a **Data Access** log?
2. What risk is indicated by an external email address (like `@gmail.com` or `@external-mail.example`) being granted `roles/owner` on a corporate GCP project?

---

## Challenge Task: Extract Unique Principals

Write a one-line Python or shell command to extract all unique `principalEmail` values across both `normal-events.jsonl` and `suspicious-events.jsonl`.

### Hint 1:
Use Python's `json` module to parse each line and collect `protoPayload.authenticationInfo.principalEmail` into a set.

### Solution:
```bash
python3 -c "import json, glob; emails = {json.loads(l).get('protoPayload',{}).get('authenticationInfo',{}).get('principalEmail') for f in glob.glob('*.jsonl') for l in open(f)}; print('\n'.join(sorted(filter(None, emails))))"
```
