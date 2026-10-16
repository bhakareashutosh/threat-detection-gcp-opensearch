# Detection Rules: GCP Cloud Audit Logs

This directory contains OpenSearch Security Analytics-compatible detection rules authored in Sigma JSON syntax for identifying suspicious behaviors in Google Cloud Platform.

---

## Detection Rules Inventory

| Rule File | Scenario | Severity | MITRE ATT&CK | Key Field Matched |
| :--- | :--- | :--- | :--- | :--- |
| `gcp_iam_binding_changed.json` | IAM Role Binding Modification | **Critical** | [T1098](https://attack.mitre.org/techniques/T1098/) | `gcp.method_name: SetIamPolicy` |
| `gcp_service_account_key_created.json` | Service Account Key Created | **High** | [T1098.001](https://attack.mitre.org/techniques/T1098/001/) | `gcp.method_name: ...CreateServiceAccountKey` |
| `gcp_firewall_rule_exposed.json` | Firewall Ingress Rule Inserted | **High** | [T1562.007](https://attack.mitre.org/techniques/T1562/007/) | `gcp.method_name: v1.compute.firewalls.insert` |
| `gcp_excessive_denied_api_calls.json` | Permission Denied Probing | **Medium** | [T1087.004](https://attack.mitre.org/techniques/T1087/004/) | `gcp.status_code: 7` |
| `gcp_logging_sink_deleted.json` | Cloud Logging Sink Deletion | **Critical** | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) | `gcp.method_name: ...DeleteSink` |

---

## Anatomy of an OpenSearch Security Analytics Rule

OpenSearch Security Analytics uses the open-source **Sigma standard** for detection rules. Rules are submitted as JSON or YAML to `POST /_plugins/_security_analytics/rules?category=<log_type>`.

A rule definition includes:
1. **Metadata**: `title`, `id` (UUID), `description`, `author`, `date`, `references`.
2. **Log Source**: `product` (e.g., `others_application`), `service`.
3. **Detection Logic**:
   - `selection`: Key-value field conditions to match.
   - `condition`: Logical expression combining selections (`selection`, `selection1 and not filter`, etc.).
4. **Classification**: `level` (`low`, `medium`, `high`, `critical`), `tags` (MITRE ATT&CK tactics & techniques), `falsepositives`.

---

## Field Mapping Integration

To match rules against the raw or normalized audit log fields, the target index maps raw GCP attributes to rule attributes:
- `gcp.method_name` -> `protoPayload.methodName`
- `gcp.service_name` -> `protoPayload.serviceName`
- `gcp.status_code`  -> `protoPayload.status.code`
- `gcp.principal`    -> `protoPayload.authenticationInfo.principalEmail`
- `gcp.caller_ip`    -> `protoPayload.requestMetadata.callerIp`

These mappings are managed using the Security Analytics Mappings API (`POST /_plugins/_security_analytics/mappings`) and document normalization.
