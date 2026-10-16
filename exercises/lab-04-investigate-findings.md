# Lab 04: Investigate Security Findings and Formulate Remediation

## Objective
In this lab, you will act as a Tier-2 SOC Analyst investigating a security finding surfaced by OpenSearch Security Analytics. You will pivot across telemetry, reconstruct the adversary's actions, assess impact, and formulate incident containment commands.

---

## Prerequisites
- Completed Lab 01, 02, and 03.
- Active detector configured in OpenSearch.
- OpenSearch Dashboards accessible at `http://localhost:5601`.

---

## Key Concepts
1. **Finding Triage**: Evaluating whether an automated match represents a legitimate administrative activity or an active security breach.
2. **Telemetry Pivoting**: Correlating events sharing common indicators (such as `principalEmail`, `callerIp`, or `insertId`) across a time window.
3. **Forensic Delta Analysis**: Examining structural diffs in cloud policies (e.g. `serviceData.policyDelta`) to determine exact permissions granted.

---

## Step-by-Step Instructions

### Step 1: Query Security Findings
Query OpenSearch Security Analytics to inspect recent findings:

```bash
curl -s -X POST "http://localhost:9200/_plugins/_security_analytics/findings/_search" \
    -H "Content-Type: application/json" \
    -d '{"query": {"match_all": {}}}' | python3 -m json.tool
```

Review the finding properties:
* `queries[0].name`: The rule that triggered the finding.
* `related_doc_ids`: The document ID (`insertId`) that produced the match.

### Step 2: Retrieve the Triggering Document
Using the `related_doc_ids` value from the finding (or `sim-threat-001-iam-escalation`), inspect the raw event:

```bash
curl -s "http://localhost:9200/gcp-audit-logs-demo/_doc/sim-threat-001-iam-escalation" | python3 -m json.tool
```

### Step 3: Analyze the IAM Policy Delta
Locate the `serviceData.policyDelta` object inside `protoPayload`:

```bash
python3 -c "import urllib.request, json; doc = json.loads(urllib.request.urlopen('http://localhost:9200/gcp-audit-logs-demo/_doc/sim-threat-001-iam-escalation').read().decode()); print(json.dumps(doc['_source']['protoPayload']['serviceData'], indent=2))"
```

Expected output:
```json
{
  "policyDelta": {
    "bindingDeltas": [
      {
        "action": "ADD",
        "member": "user:attacker-exfil@external-mail.example",
        "role": "roles/owner"
      }
    ]
  }
}
```

### Analysis Checklist:
- [x] **Actor**: `compromised-admin@demo-corp.internal`
- [x] **Caller IP**: `198.51.100.45`
- [x] **Beneficiary**: `attacker-exfil@external-mail.example`
- [x] **Role Granted**: `roles/owner` (Full administrative control over all GCP resources in the project)

### Step 4: Pivot by Attacker Email
Search for all operations involving the external beneficiary across the cluster:

```bash
curl -s -X POST "http://localhost:9200/gcp-audit-logs-demo/_search" \
    -H "Content-Type: application/json" \
    -d '{
      "query": {
        "term": { "gcp.principal": "attacker-exfil@external-mail.example" }
      }
    }' | python3 -c "import sys, json; hits = json.load(sys.stdin)['hits']['hits']; print('\n'.join(f'{h[\"_source\"][\"gcp\"][\"method_name\"]} -> {h[\"_source\"][\"gcp\"][\"resource_name\"]}' for h in hits))"
```

Notice the attacker's progression:
1. `google.iam.admin.v1.CreateServiceAccountKey`: Created a persistent service account key.
2. `v1.compute.firewalls.insert`: Opened firewall port 22 to the internet.
3. `google.logging.v2.ConfigServiceV2.DeleteSink`: Deleted the SIEM logging sink to blind incident responders!

---

## Validation Steps: Formulate Remediation Commands
Based on your investigation, draft the remediation commands to contain the threat:

1. **Revert IAM Role**:
   ```bash
   gcloud projects remove-iam-policy-binding demo-student-project \
       --member="user:attacker-exfil@external-mail.example" \
       --role="roles/owner"
   ```
2. **Revoke Service Account Key**:
   ```bash
   gcloud iam service-accounts keys delete [KEY_ID] \
       --iam-account="data-exporter@demo-student-project.iam.gserviceaccount.com"
   ```
3. **Delete Exposed Firewall Rule**:
   ```bash
   gcloud compute firewall-rules delete allow-all-ssh-world
   ```

---

## Questions for Students
1. Why did the attacker delete the Cloud Logging sink?
2. If this were a real attack, what should you do with the account `compromised-admin@demo-corp.internal`?

---

## Challenge Task: Reconstruct the Complete Attack Timeline

Write a script or query that prints all suspicious events sorted chronologically by `@timestamp`, displaying:
`[Timestamp] [Principal] -> [Action] on [Resource]`

### Solution:
```bash
python3 -c "import urllib.request, json; data = json.loads(urllib.request.urlopen(urllib.request.Request('http://localhost:9200/gcp-audit-logs-demo/_search', data=b'{\"query\":{\"prefix\":{\"insertId\":\"sim-threat\"}},\"sort\":[{\"@timestamp\":{\"order\":\"asc\"}}],\"size\":20}', headers={'Content-Type':'application/json'})).read().decode()); print('\n'.join(f'{h[\"_source\"][\"@timestamp\"]} | {h[\"_source\"][\"gcp\"][\"principal\"]:35s} | {h[\"_source\"][\"gcp\"][\"method_name\"]:45s}' for h in data['hits']['hits']))"
```
