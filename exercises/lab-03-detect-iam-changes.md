# Lab 03: Detect IAM Privilege Escalation with Security Analytics

## Objective
In this lab, you will configure OpenSearch Security Analytics to detect suspicious IAM role modifications in GCP Cloud Audit Logs using Sigma detection rules and automated detectors.

---

## Prerequisites
- Completed Lab 01 and Lab 02.
- Telemetry indexed in `gcp-audit-logs-demo`.
- OpenSearch Security Analytics plugin verified active.

---

## Key Concepts
1. **Sigma Specification**: A generic, open-source rule format for describing security event patterns across heterogeneous SIEM platforms.
2. **Security Analytics Detector**: A scheduled background job that compiles Sigma rules into OpenSearch queries and scans target indices on an interval.
3. **Log Types & Field Mappings**: Categorizes incoming events and maps arbitrary telemetry fields into the attributes evaluated by detection rules.

---

## Step-by-Step Instructions

### Step 1: Examine the IAM Detection Rule
Inspect the custom Sigma rule defined in `detection-rules/custom-rules/gcp_iam_binding_changed.json`:

```bash
cat detection-rules/custom-rules/gcp_iam_binding_changed.json | python3 -m json.tool
```

Review the `detection` block:
```json
"detection": {
    "selection": {
        "gcp.method_name": "SetIamPolicy"
    },
    "condition": "selection"
}
```

### Step 2: Configure Detectors and Rules
Run the automated configuration script:

```bash
make configure-detectors
```

Expected output:
```text
================================================================================
 OpenSearch Security Analytics Configuration
================================================================================
Target Cluster: http://localhost:9200
Target Index:   gcp-audit-logs-demo
Detector Name:  gcp-threat-detector
[+] OpenSearch Security Analytics plugin is verified active.
[*] Loading 5 custom detection rules...
    [+] Created rule: 'GCP Permission Denied API Call Attempt'
    [+] Created rule: 'GCP Firewall Ingress Rule Created or Modified'
    [+] Created rule: 'GCP IAM Role Binding Modification'
    [+] Created rule: 'GCP Cloud Logging Sink Deletion'
    [+] Created rule: 'GCP Service Account Key Created'
[+] Successfully created detector 'gcp-threat-detector' (ID: ...).
================================================================================
```

### Step 3: Verify Registered Rules via REST API
Query the Security Analytics Rule API:

```bash
curl -s -X POST "http://localhost:9200/_plugins/_security_analytics/rules/_search?category=others_application" \
    -H "Content-Type: application/json" \
    -d '{"query": {"match_all": {}}}' | python3 -m json.tool
```

Verify that 5 custom rules are returned.

### Step 4: Verify Active Detector Configuration
Query the Detector API:

```bash
curl -s -X POST "http://localhost:9200/_plugins/_security_analytics/detectors/_search" \
    -H "Content-Type: application/json" \
    -d '{"query": {"match_all": {}}}' | python3 -m json.tool
```

Confirm that:
- `"name"` is `"gcp-threat-detector"`.
- `"enabled"` is `true`.
- `"indices"` includes `["gcp-audit-logs-demo"]`.

---

## Validation Steps
Run the scenario test suite to verify that the detector matches the indexed IAM escalation event:

```bash
make test
```

Confirm that `SCENARIO-1: IAM Role Binding Modification (SetIamPolicy)` reports `[PASS]`.

---

## Common Mistakes & Troubleshooting
* **`HTTP 400 detector_type not supported`**: Ensure your detector uses `others_application` as the log type category.
* **Detector rule count is 0**: Verify that custom rule files exist in `detection-rules/custom-rules/` and contain valid JSON.

---

## Questions for Students
1. How does the Sigma rule standard allow SOC teams to avoid vendor lock-in?
2. If an attacker modifies IAM policy using `google.iam.admin.v1.SetIamPolicy` instead of `SetIamPolicy`, how should the detection rule selection be updated?

---

## Challenge Task: Inspect Rule Tags

Write a query to list all MITRE ATT&CK technique tags associated with the rules registered in your detector.

### Hint 1:
Query `_plugins/_security_analytics/rules/_search` and extract `_source.tags[*].value`.

### Solution:
```bash
python3 -c "import urllib.request, json; data = json.loads(urllib.request.urlopen(urllib.request.Request('http://localhost:9200/_plugins/_security_analytics/rules/_search?category=others_application', data=b'{\"query\":{\"match_all\":{}}}', headers={'Content-Type':'application/json'})).read().decode()); print('\n'.join(sorted({t['value'] for hit in data['hits']['hits'] for t in hit['_source'].get('tags',[])})))"
```
