# Instructor Guide: GCP Threat Detection with OpenSearch

This guide is designed for technical instructors, DevSecOps workshop facilitators, and university lecturers delivering this lab in a classroom, training, or workshop setting.

---

## 1. 15-Minute Lecture / Presentation Plan

| Minute | Topic | Key Talking Points | Visuals / Artifacts |
| :--- | :--- | :--- | :--- |
| **00:00 - 03:00** | Cloud Visibility Challenge | Why perimeter security fails in cloud; IAM is the new perimeter; API calls are the modern network packets. | Slide / Diagram from [docs/architecture.md](file:///c:/Users/cidco/Documents/OpenSearch%20+%20GCP%20Demo/docs/architecture.md) |
| **03:00 - 07:00** | GCP Cloud Audit Logs Architecture | Admin Activity (Always ON, 400d free) vs Data Access (billable, 30d); anatomy of `AuditLog` Protobuf. | Sample log from [sample-data/normal-events.jsonl](file:///c:/Users/cidco/Documents/OpenSearch%20+%20GCP%20Demo/sample-data/normal-events.jsonl) |
| **07:00 - 11:00** | Ingestion, Normalization, & OpenSearch | Why raw logs must be mapped; OpenSearch Ingest Pipelines; idempotency using `insertId`. | [config/pipelines/log-normalization-pipeline.json](file:///c:/Users/cidco/Documents/OpenSearch%20+%20GCP%20Demo/config/pipelines/log-normalization-pipeline.json) |
| **11:00 - 15:00** | Detection Engineering with Security Analytics | Open-source Sigma standard; Detectors, Findings vs Alerts; 5 key cloud attack scenarios. | [docs/detection-rules.md](file:///c:/Users/cidco/Documents/OpenSearch%20+%20GCP%20Demo/docs/detection-rules.md) |

---

## 2. Five-Minute Live Attack Simulation Walkthrough

Use this scripted demonstration to captivate students before they begin hands-on labs:

```bash
# Terminal Demo: Live Ingestion and Attack Detection in 5 Minutes

# 1. Show the clean cluster state (1 minute)
make health-check

# 2. Ingest the attack telemetry (1 minute)
make ingest

# 3. Trigger detector setup (1 minute)
make configure-detectors

# 4. Demonstrate the 5 attack scenarios detected (2 minutes)
make test
```

### Scripted Instructor Narration:
1. *"Notice that our raw GCP logs contain a routine admin operation alongside an attacker elevating privileges."*
2. *"Look at `sim-threat-001-iam-escalation`: An adversary called `SetIamPolicy` to add `attacker-exfil@external-mail.example` as `roles/owner`."*
3. *"OpenSearch normalized these fields and our Sigma rule detected the technique immediately!"*
4. *"Now open OpenSearch Dashboards at `http://localhost:5601` to show students the visual timeline and findings dashboard."*

---

## 3. Expected Student Evidence to Capture

Instructors assessing student lab completion should require the following artifacts:
1. **Lab 01**: Extracted `principalEmail`, `methodName`, and `callerIp` from the sample JSONL file.
2. **Lab 02**: Terminal output or screenshot of `make ingest` confirming:
   ```text
   Total verified documents in index 'gcp-audit-logs-demo': 16
   ```
3. **Lab 03**: OpenSearch REST query showing active detector status:
   ```json
   GET /_plugins/_security_analytics/detectors/_search
   ```
4. **Lab 04**: Finding detail JSON showing `sim-threat-001-iam-escalation` correlated with MITRE T1098.
5. **Lab 05**: The custom Sigma JSON rule file created by the student and the verification output from `pytest tests/`.

---

## 4. Student Assessment Questions & Answer Key

### Q1: Why is Admin Activity logging always enabled while Data Access logging is disabled by default?
* **Answer**: Admin Activity records control plane modifications (resource creation, IAM changes) which are critical for security and low-to-moderate volume. Data Access logs record individual data object access (reading Cloud Storage files, querying BigQuery tables), which can generate millions of events per minute and incur massive storage costs.

### Q2: What is the risk of using user-managed Service Account keys instead of workload identity federation?
* **Answer**: User-managed service account keys are static JSON credentials containing RSA private keys. Once downloaded, they can be stolen, leaked on GitHub, or exfiltrated, allowing attackers to access cloud APIs from any machine without IP or device controls.

### Q3: What is the difference between an OpenSearch Security Analytics Finding and an Alert?
* **Answer**: A **Finding** is generated every time a log document matches a detection rule (evidence of interest). An **Alert** is generated only when finding criteria meet a configured notification trigger (e.g. critical severity), dispatching a pager or chat message.

### Q4: Why is it important to use GCP `insertId` as the document `_id` during ingestion?
* **Answer**: To guarantee **idempotency**. If a network failure occurs and log batches are re-transmitted, OpenSearch overwrites the existing document rather than creating duplicate events that could skew detection counts and trigger false alerts.

---

## 5. Common Student Mistakes & Rapid Fixes

1. **Containers Won't Start (Port Conflict)**:
   - *Cause*: Local Docker, MySQL, or another service is listening on port 9200 or 5601.
   - *Fix*: Check with `netstat -ano | findstr 9200` (Windows) or `lsof -i :9200` (Mac/Linux). Stop conflicting process or change `OPENSEARCH_PORT` in `.env`.
2. **WSL2 Timeout / Containers Exiting (Exit code 143)**:
   - *Cause*: Windows WSL2 idle timeout shutting down when interactive terminal is closed.
   - *Fix*: Run a background daemon session: `wsl -d Ubuntu -u root -- sleep infinity &`.
3. **Missing Index Pipeline**:
   - *Cause*: Creating index manually before registering the pipeline.
   - *Fix*: Run `make ingest`, which automatically creates the pipeline and re-indexes.

---

## 6. Classroom Reset Procedure

Between classroom sessions or student groups, reset the entire environment in 30 seconds:

```bash
# Complete reset
make cleanup
make setup
make start
```
