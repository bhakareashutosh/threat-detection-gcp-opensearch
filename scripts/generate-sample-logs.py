#!/usr/bin/env python3
"""
Generate realistic synthetic GCP Cloud Audit Logs for educational threat detection.

All events are strictly synthetic and labeled as educational simulations.
No real credentials, production identifiers, or private data are contained.
"""

import json
import os
import uuid
from datetime import datetime, timezone, timedelta

def get_base_event(insert_id, timestamp_str, log_type, service_name, method_name,
                   principal_email, caller_ip, resource_name, resource_type,
                   project_id="demo-student-project", status_code=0, status_message="",
                   severity="NOTICE", user_agent="google-cloud-sdk/460.0.0"):
    """Constructs a standard GCP Cloud Audit Log envelope."""
    
    # Standard logName formats:
    # Admin Activity: projects/{project}/logs/cloudaudit.googleapis.com%2Factivity
    # Data Access: projects/{project}/logs/cloudaudit.googleapis.com%2Fdata_access
    log_name = f"projects/{project_id}/logs/cloudaudit.googleapis.com%2F{log_type}"

    event = {
        "insertId": insert_id,
        "logName": log_name,
        "timestamp": timestamp_str,
        "severity": severity,
        "resource": {
            "type": resource_type,
            "labels": {
                "project_id": project_id,
                "location": "us-central1"
            }
        },
        "protoPayload": {
            "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
            "serviceName": service_name,
            "methodName": method_name,
            "resourceName": resource_name,
            "authenticationInfo": {
                "principalEmail": principal_email,
                "callerIp": caller_ip,
                "callerSuppliedUserAgent": user_agent
            },
            "requestMetadata": {
                "callerIp": caller_ip,
                "callerNetwork": "network-external"
            },
            "status": {
                "code": status_code,
                "message": status_message
            }
        },
        "simulationMetadata": {
            "synthetic": True,
            "lab": "Threat Detection on GCP Audit Logs with OpenSearch",
            "environment": "educational-sandbox"
        }
    }
    return event


def generate_normal_events(base_time):
    """Generates routine, benign GCP administrative and operational activity."""
    events = []
    
    # 1. Routine VM instance list by DevOps engineer
    t1 = (base_time - timedelta(minutes=45)).isoformat() + "Z"
    e1 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t1,
        log_type="data_access",
        service_name="compute.googleapis.com",
        method_name="v1.compute.instances.list",
        principal_email="devops-engineer@demo-corp.internal",
        caller_ip="192.0.2.14",
        resource_name="projects/demo-student-project/zones/us-central1-a/instances",
        resource_type="gce_instance",
        severity="INFO"
    )
    events.append(e1)

    # 2. Routine Cloud Storage bucket metadata inspection
    t2 = (base_time - timedelta(minutes=40)).isoformat() + "Z"
    e2 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t2,
        log_type="data_access",
        service_name="storage.googleapis.com",
        method_name="storage.buckets.get",
        principal_email="ci-cd-service-account@demo-student-project.iam.gserviceaccount.com",
        caller_ip="192.0.2.55",
        resource_name="projects/_/buckets/demo-application-assets",
        resource_type="gcs_bucket",
        severity="INFO"
    )
    events.append(e2)

    # 3. Scheduled VM start during morning maintenance window
    t3 = (base_time - timedelta(minutes=35)).isoformat() + "Z"
    e3 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t3,
        log_type="activity",
        service_name="compute.googleapis.com",
        method_name="v1.compute.instances.start",
        principal_email="scheduler@demo-student-project.iam.gserviceaccount.com",
        caller_ip="192.0.2.100",
        resource_name="projects/demo-student-project/zones/us-central1-a/instances/worker-node-01",
        resource_type="gce_instance",
        severity="NOTICE"
    )
    events.append(e3)

    # 4. Project get metadata call from GCP console
    t4 = (base_time - timedelta(minutes=30)).isoformat() + "Z"
    e4 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t4,
        log_type="data_access",
        service_name="cloudresourcemanager.googleapis.com",
        method_name="GetProject",
        principal_email="lead-architect@demo-corp.internal",
        caller_ip="192.0.2.18",
        resource_name="projects/demo-student-project",
        resource_type="project",
        severity="INFO"
    )
    events.append(e4)

    # 5. Routine Cloud Logging query execution
    t5 = (base_time - timedelta(minutes=25)).isoformat() + "Z"
    e5 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t5,
        log_type="data_access",
        service_name="logging.googleapis.com",
        method_name="google.logging.v2.LoggingServiceV2.ListLogEntries",
        principal_email="security-auditor@demo-corp.internal",
        caller_ip="192.0.2.80",
        resource_name="projects/demo-student-project",
        resource_type="project",
        severity="INFO"
    )
    events.append(e5)

    # 6. Routine IAM service account listing
    t6 = (base_time - timedelta(minutes=20)).isoformat() + "Z"
    e6 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t6,
        log_type="data_access",
        service_name="iam.googleapis.com",
        method_name="google.iam.admin.v1.ListServiceAccounts",
        principal_email="devops-engineer@demo-corp.internal",
        caller_ip="192.0.2.14",
        resource_name="projects/demo-student-project",
        resource_type="service_account",
        severity="INFO"
    )
    events.append(e6)

    # 7. Benign Compute Engine disk snapshot creation
    t7 = (base_time - timedelta(minutes=15)).isoformat() + "Z"
    e7 = get_base_event(
        insert_id=f"sim-norm-{uuid.uuid4().hex[:8]}",
        timestamp_str=t7,
        log_type="activity",
        service_name="compute.googleapis.com",
        method_name="v1.compute.disks.createSnapshot",
        principal_email="backup-service@demo-student-project.iam.gserviceaccount.com",
        caller_ip="192.0.2.105",
        resource_name="projects/demo-student-project/zones/us-central1-a/disks/data-disk-prod",
        resource_type="gce_disk",
        severity="NOTICE"
    )
    events.append(e7)

    return events


def generate_suspicious_events(base_time):
    """Generates realistic security incident events mapped to MITRE ATT&CK for Cloud."""
    events = []

    # Threat Scenario 1: IAM Role Binding Modification (Privilege Escalation / Persistence - MITRE T1098)
    # Compromised admin account assigns Owner privileges to an external untrusted Gmail account
    t1 = (base_time - timedelta(minutes=14)).isoformat() + "Z"
    e1 = get_base_event(
        insert_id="sim-threat-001-iam-escalation",
        timestamp_str=t1,
        log_type="activity",
        service_name="iam.googleapis.com",
        method_name="SetIamPolicy",
        principal_email="compromised-admin@demo-corp.internal",
        caller_ip="198.51.100.45",
        resource_name="projects/demo-student-project",
        resource_type="project",
        severity="WARNING"
    )
    e1["protoPayload"]["serviceData"] = {
        "policyDelta": {
            "bindingDeltas": [
                {
                    "action": "ADD",
                    "role": "roles/owner",
                    "member": "user:attacker-exfil@external-mail.example"
                }
            ]
        }
    }
    e1["threatContext"] = {
        "scenario": "IAM Role Binding Modification",
        "mitre_technique": "T1098 - Account Manipulation",
        "severity": "CRITICAL",
        "indicator": "roles/owner assigned to external untrusted identity"
    }
    events.append(e1)

    # Threat Scenario 2: Service Account Key Creation (Credential Access / Backdoor - MITRE T1098.001)
    # Attacker generates user-managed service account key to establish persistent out-of-band access
    t2 = (base_time - timedelta(minutes=11)).isoformat() + "Z"
    e2 = get_base_event(
        insert_id="sim-threat-002-sa-key-created",
        timestamp_str=t2,
        log_type="activity",
        service_name="iam.googleapis.com",
        method_name="google.iam.admin.v1.CreateServiceAccountKey",
        principal_email="attacker-exfil@external-mail.example",
        caller_ip="198.51.100.45",
        resource_name="projects/demo-student-project/serviceAccounts/data-exporter@demo-student-project.iam.gserviceaccount.com",
        resource_type="service_account",
        severity="WARNING"
    )
    e2["threatContext"] = {
        "scenario": "Service Account Key Creation",
        "mitre_technique": "T1098.001 - Additional Cloud Credentials",
        "severity": "HIGH",
        "indicator": "Service account private key generated by external principal"
    }
    events.append(e2)

    # Threat Scenario 3: Firewall Rule Modification to Expose Sensitive Port (Defense Evasion / Initial Access - MITRE T1562.007)
    # Ingress rule modified to allow port 22 (SSH) open to entire world (0.0.0.0/0)
    t3 = (base_time - timedelta(minutes=8)).isoformat() + "Z"
    e3 = get_base_event(
        insert_id="sim-threat-003-firewall-open",
        timestamp_str=t3,
        log_type="activity",
        service_name="compute.googleapis.com",
        method_name="v1.compute.firewalls.insert",
        principal_email="attacker-exfil@external-mail.example",
        caller_ip="198.51.100.45",
        resource_name="projects/demo-student-project/global/firewalls/allow-all-ssh-world",
        resource_type="gce_firewall_rule",
        severity="WARNING"
    )
    e3["protoPayload"]["request"] = {
        "name": "allow-all-ssh-world",
        "sourceRanges": ["0.0.0.0/0"],
        "allowed": [{"IPProtocol": "tcp", "ports": ["22"]}]
    }
    e3["threatContext"] = {
        "scenario": "Firewall Rule Opened to Internet",
        "mitre_technique": "T1562.007 - Disable or Modify Cloud Firewall",
        "severity": "HIGH",
        "indicator": "Inbound TCP 22 permitted from 0.0.0.0/0"
    }
    events.append(e3)

    # Threat Scenario 4: Excessive Denied API Calls (Discovery / Unauthorized Access - MITRE T1087.004)
    # Series of unauthorized attempts to read secrets from Secret Manager
    for i in range(1, 6):
        t_denied = (base_time - timedelta(minutes=6, seconds=45 - (i * 7))).isoformat() + "Z"
        e_denied = get_base_event(
            insert_id=f"sim-threat-004-denied-{i:03d}",
            timestamp_str=t_denied,
            log_type="data_access",
            service_name="secretmanager.googleapis.com",
            method_name="google.cloud.secretmanager.v1.SecretManagerService.AccessSecretVersion",
            principal_email="compromised-contractor@demo-corp.internal",
            caller_ip="203.0.113.88",
            resource_name=f"projects/demo-student-project/secrets/prod-database-creds-{i}/versions/latest",
            resource_type="secretmanager.googleapis.com/Secret",
            status_code=7,  # PERMISSION_DENIED
            status_message="Permission denied on resource (or it may not exist).",
            severity="ERROR"
        )
        e_denied["threatContext"] = {
            "scenario": "Repeated Denied API Calls",
            "mitre_technique": "T1552 - Unsecured Credentials / Discovery",
            "severity": "MEDIUM",
            "attempt_number": i
        }
        events.append(e_denied)

    # Threat Scenario 5: Audit Logging Sink Deletion (Defense Evasion / Log Tampering - MITRE T1562.008)
    # Attacker removes central log exporter sink to blind SIEM and incident responders
    t5 = (base_time - timedelta(minutes=2)).isoformat() + "Z"
    e5 = get_base_event(
        insert_id="sim-threat-005-sink-deleted",
        timestamp_str=t5,
        log_type="activity",
        service_name="logging.googleapis.com",
        method_name="google.logging.v2.ConfigServiceV2.DeleteSink",
        principal_email="attacker-exfil@external-mail.example",
        caller_ip="198.51.100.45",
        resource_name="projects/demo-student-project/sinks/siem-opensearch-export-sink",
        resource_type="logging_sink",
        severity="CRITICAL"
    )
    e5["threatContext"] = {
        "scenario": "Cloud Logging Sink Deletion",
        "mitre_technique": "T1562.008 - Disable Cloud Logging",
        "severity": "CRITICAL",
        "indicator": "Audit log export sink to OpenSearch SIEM was deleted"
    }
    events.append(e5)

    return events


def main():
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    sample_dir = os.path.join(repo_root, "sample-data")
    os.makedirs(sample_dir, exist_ok=True)

    base_time = datetime.now(timezone.utc)

    normal_events = generate_normal_events(base_time)
    suspicious_events = generate_suspicious_events(base_time)

    normal_file = os.path.join(sample_dir, "normal-events.jsonl")
    with open(normal_file, "w", encoding="utf-8") as f:
        for event in normal_events:
            f.write(json.dumps(event) + "\n")

    suspicious_file = os.path.join(sample_dir, "suspicious-events.jsonl")
    with open(suspicious_file, "w", encoding="utf-8") as f:
        for event in suspicious_events:
            f.write(json.dumps(event) + "\n")

    print(f"[+] Successfully generated synthetic GCP audit logs:")
    print(f"    - Normal events:     {len(normal_events):2d} records -> {normal_file}")
    print(f"    - Suspicious events: {len(suspicious_events):2d} records -> {suspicious_file}")
    print(f"    Total:               {len(normal_events) + len(suspicious_events)} records")

if __name__ == "__main__":
    main()
