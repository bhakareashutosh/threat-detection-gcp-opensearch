# Sample Data: Synthetic GCP Cloud Audit Logs

This directory contains representative, deterministic, synthetic GCP Cloud Audit Log records in JSON Lines (`.jsonl`) format for educational training and local detector validation.

> [!IMPORTANT]
> **Synthetic Data Notice**: All records in this directory are 100% synthetic simulations. They use fictitious GCP project IDs (`demo-student-project`), RFC 5737 documentation IP ranges (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`), and mock identities. No live cloud resources or real credentials are referenced.

---

## Files in this Directory

| File | Description | Event Count |
| :--- | :--- | :--- |
| `normal-events.jsonl` | Routine, benign administrative and operational events | 7 |
| `suspicious-events.jsonl` | Simulated malicious cloud activities mapped to MITRE ATT&CK | 9 |

---

## Log Categories Represented

GCP Cloud Audit Logs are categorized into distinct streams, reflected in the `logName` field:

1. **Admin Activity (`.../cloudaudit.googleapis.com%2Factivity`)**:
   - Configuration and state modifications (e.g., `SetIamPolicy`, `CreateServiceAccountKey`, `v1.compute.firewalls.insert`, `DeleteSink`).
   - Always enabled, retained for 400 days at no cost in real GCP projects.
2. **Data Access (`.../cloudaudit.googleapis.com%2Fdata_access`)**:
   - Resource inspection and API access (e.g., `instances.list`, `buckets.get`, `AccessSecretVersion`).
   - Denied access attempts (`PERMISSION_DENIED`, status code 7).

---

## Suspicious Scenarios Breakdown

The events in `suspicious-events.jsonl` model five core cloud attack techniques:

| Scenario | GCP API Method | MITRE ATT&CK | Description |
| :--- | :--- | :--- | :--- |
| **1. IAM Role Escalation** | `SetIamPolicy` | **T1098**: Account Manipulation | External attacker assigns `roles/owner` to an external identity |
| **2. Service Account Key Creation** | `CreateServiceAccountKey` | **T1098.001**: Additional Cloud Credentials | Private key generated for data exporter service account |
| **3. Firewall Rule Exposure** | `v1.compute.firewalls.insert` | **T1562.007**: Modify Cloud Firewall | Ingress rule opened to `0.0.0.0/0` on port 22 (SSH) |
| **4. Repeated Denied Calls** | `AccessSecretVersion` | **T1552**: Unsecured Credentials | 5 repeated permission-denied requests searching for secrets |
| **5. Log Sink Deletion** | `DeleteSink` | **T1562.008**: Disable Cloud Logging | Central export sink deleted to blind security monitoring |

---

## Regenerating Data

You can regenerate or refresh the timestamps on these logs at any time:

```bash
make generate-logs
# Or:
python3 scripts/generate-sample-logs.py
```
