# Detection Rules Guide: GCP Cloud Audit Logs

This guide documents the detection rules provided in this repository, the threat models they address, their Sigma logic, triage procedures, and known limitations.

---

## Detection Engineering Matrix

| Rule ID | Scenario | MITRE ATT&CK | Severity | Log Type | Key Trigger Field |
| :--- | :--- | :--- | :--- | :--- | :--- |
| `a1b2c3d4-...-81` | IAM Role Binding Modification | **T1098**: Account Manipulation | **Critical** | `others_application` | `gcp.method_name: SetIamPolicy` |
| `a1b2c3d4-...-82` | Service Account Key Created | **T1098.001**: Cloud Credentials | **High** | `others_application` | `gcp.method_name: ...CreateServiceAccountKey` |
| `a1b2c3d4-...-83` | Firewall Opened to Internet | **T1562.007**: Modify Cloud Firewall | **High** | `others_application` | `gcp.method_name: v1.compute.firewalls.insert` |
| `a1b2c3d4-...-84` | Repeated Permission Denied | **T1087.004**: Credential/Discovery | **Medium** | `others_application` | `gcp.status_code: 7` |
| `a1b2c3d4-...-85` | Log Export Sink Deleted | **T1562.008**: Disable Cloud Logging | **Critical** | `others_application` | `gcp.method_name: ...DeleteSink` |

---

## Deep Dive: Scenario 1 — IAM Role Binding Modification

### 1. Threat Scenario
An adversary compromises credentials belonging to an existing administrator or uses an over-privileged service account to grant themselves or an external account `roles/owner` or `roles/editor` on the project. This establishes persistent administrative control.

### 2. Relevant Telemetry Fields
* `protoPayload.serviceName`: `iam.googleapis.com` or `cloudresourcemanager.googleapis.com`
* `protoPayload.methodName`: `SetIamPolicy` or `google.iam.admin.v1.SetIamPolicy`
* `protoPayload.authenticationInfo.principalEmail`: Identity executing the change
* `protoPayload.serviceData.policyDelta`: Details of added members and roles

### 3. Detection Logic (Sigma)
```yaml
selection:
  gcp.method_name: "SetIamPolicy"
condition: selection
```

### 4. False Positives & Tuning
* **Benign Causes**: Automated Terraform/Pulumi CI/CD pipelines applying approved IAM changes; quarterly access recertification scripts.
* **Tuning Recommendations**: Whitelist approved deployment service accounts (e.g. `terraform-runner@*.iam.gserviceaccount.com`). Filter out actions matching approved change request IDs in `protoPayload.requestMetadata.callerSuppliedUserAgent`.

### 5. Investigation Workflow
1. Identify the caller: Check `protoPayload.authenticationInfo.principalEmail` and `callerIp`.
2. Inspect `serviceData.policyDelta.bindingDeltas`: Determine which member was granted what role.
3. Verify if the member email belongs to an authorized corporate domain (e.g., `@example.com` vs `@gmail.com`).
4. Revert unauthorized role grants immediately using `gcloud projects remove-iam-policy-binding`.

---

## Deep Dive: Scenario 2 — Service Account Key Creation

### 1. Threat Scenario
Adversaries create user-managed private keys for Google Cloud Service Accounts (`CreateServiceAccountKey`). Unlike Google-managed keys which rotate automatically and never leave Google infrastructure, user-managed keys can be downloaded as JSON files and used anywhere on the internet without VPN or device restrictions.

### 2. Relevant Telemetry Fields
* `protoPayload.serviceName`: `iam.googleapis.com`
* `protoPayload.methodName`: `google.iam.admin.v1.CreateServiceAccountKey`
* `protoPayload.resourceName`: Target service account email path
* `protoPayload.authenticationInfo.principalEmail`: Actor creating the key

### 3. Detection Logic (Sigma)
```yaml
selection:
  gcp.method_name: "google.iam.admin.v1.CreateServiceAccountKey"
condition: selection
```

### 4. False Positives & Tuning
* **Benign Causes**: Developer provisioning keys for local testing; third-party SaaS integration setup.
* **Organization Policy**: Enforce `iam.disableServiceAccountKeyCreation` at the GCP Organization or Folder level to block key creation organization-wide.

### 5. Investigation Workflow
1. Check the target service account: Does it have high privileges (`Owner`, `Security Admin`)?
2. Check the actor: Is this a developer or an unrecognized external identity?
3. Remediate: Revoke the newly created key immediately:
   ```bash
   gcloud iam service-accounts keys delete [KEY_ID] --iam-account=[SA_EMAIL]
   ```

---

## Deep Dive: Scenario 3 — Firewall Ingress Rule Opened to Internet

### 1. Threat Scenario
An attacker modifies or creates a Compute Engine firewall rule to allow inbound traffic from `0.0.0.0/0` (the entire public internet) on sensitive administrative ports like TCP 22 (SSH) or TCP 3389 (RDP). This exposes internal compute workloads to automated scanning and brute-force attacks.

### 2. Relevant Telemetry Fields
* `protoPayload.serviceName`: `compute.googleapis.com`
* `protoPayload.methodName`: `v1.compute.firewalls.insert` or `v1.compute.firewalls.patch`
* `protoPayload.request.sourceRanges`: Array containing `0.0.0.0/0`
* `protoPayload.request.allowed`: Protocols and ports allowed

### 3. Detection Logic (Sigma)
```yaml
selection:
  gcp.method_name: "v1.compute.firewalls.insert"
condition: selection
```

### 4. Investigation Workflow
1. Inspect the rule definition in `protoPayload.request`.
2. Check which network and target tags are assigned.
3. If internet ingress is unauthorized, delete or patch the firewall rule immediately:
   ```bash
   gcloud compute firewall-rules delete [FIREWALL_RULE_NAME]
   ```

---

## Deep Dive: Scenario 4 — Repeated Permission Denied Probing

### 1. Threat Scenario
A compromised identity attempts to access multiple resources (e.g., listing Cloud Storage buckets, reading secrets in Secret Manager, querying BigQuery tables) without having the appropriate IAM permissions. This pattern indicates automated discovery or privilege testing.

### 2. Relevant Telemetry Fields
* `protoPayload.status.code`: `7` (`PERMISSION_DENIED`)
* `protoPayload.status.message`: Error message returned to caller
* `protoPayload.resourceName`: Target resource attempted

### 3. Detection Logic (Sigma)
```yaml
selection:
  gcp.status_code: 7
condition: selection
```

### 4. Investigation Workflow
1. Group denied events by `principalEmail` and `callerIp`.
2. Review the timeline: Are requests occurring within seconds across disparate services?
3. Check if the account has recently shown signs of compromise (unusual login location, impossible travel).

---

## Deep Dive: Scenario 5 — Cloud Logging Sink Deletion

### 1. Threat Scenario
To evade detection and disable SIEM visibility, an intruder deletes the centralized Cloud Logging sink exporting telemetry to OpenSearch or Pub/Sub.

### 2. Relevant Telemetry Fields
* `protoPayload.serviceName`: `logging.googleapis.com`
* `protoPayload.methodName`: `google.logging.v2.ConfigServiceV2.DeleteSink`
* `protoPayload.resourceName`: Identifier of deleted sink

### 3. Detection Logic (Sigma)
```yaml
selection:
  gcp.method_name: "google.logging.v2.ConfigServiceV2.DeleteSink"
condition: selection
```

### 4. Investigation Workflow
1. This is a **Critical** severity incident. Immediately notify the incident response team.
2. Check `authenticationInfo.principalEmail` and quarantine the identity.
3. Re-create the export sink to restore logging continuity.
