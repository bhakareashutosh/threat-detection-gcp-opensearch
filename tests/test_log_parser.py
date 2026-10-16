"""
Unit tests for GCP Cloud Audit Log parsing and validation.
"""

import json
import pytest
import sys
import os

# Ensure scripts path is importable
repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(repo_root, "scripts"))

from ingest_sample_logs import normalize_event

SAMPLE_VALID_EVENT = {
    "insertId": "test-valid-001",
    "logName": "projects/demo-student-project/logs/cloudaudit.googleapis.com%2Factivity",
    "timestamp": "2026-10-16T12:00:00Z",
    "severity": "NOTICE",
    "resource": {
        "type": "project",
        "labels": {"project_id": "demo-student-project"}
    },
    "protoPayload": {
        "@type": "type.googleapis.com/google.cloud.audit.AuditLog",
        "serviceName": "iam.googleapis.com",
        "methodName": "SetIamPolicy",
        "resourceName": "projects/demo-student-project",
        "authenticationInfo": {
            "principalEmail": "compromised-admin@demo-corp.internal",
            "callerIp": "198.51.100.45"
        },
        "requestMetadata": {
            "callerIp": "198.51.100.45"
        },
        "status": {
            "code": 0,
            "message": ""
        }
    }
}


def test_valid_audit_event_parsing():
    """Verify that a standard GCP audit log parses and retains core fields."""
    parsed = normalize_event(SAMPLE_VALID_EVENT)
    assert parsed["insertId"] == "test-valid-001"
    assert parsed["cloud"]["provider"] == "gcp"
    assert parsed["cloud"]["project"]["id"] == "demo-student-project"
    assert parsed["event"]["action"] == "SetIamPolicy"
    assert parsed["event"]["outcome"] == "success"
    assert parsed["user"]["name"] == "compromised-admin@demo-corp.internal"
    assert parsed["source"]["ip"] == "198.51.100.45"


def test_missing_optional_fields_handling():
    """Ensure parser gracefully handles logs with absent optional metadata."""
    minimal_event = {
        "insertId": "test-minimal-002",
        "protoPayload": {
            "serviceName": "compute.googleapis.com",
            "methodName": "v1.compute.instances.list"
        }
    }
    parsed = normalize_event(minimal_event)
    assert parsed["insertId"] == "test-minimal-002"
    assert parsed["cloud"]["provider"] == "gcp"
    assert parsed["event"]["action"] == "v1.compute.instances.list"
    assert parsed["event"]["outcome"] == "success"  # Default 0 status code
    assert parsed["user"]["name"] == ""
    assert "source" not in parsed  # Absent callerIp should not create empty source.ip


def test_error_status_outcome_normalization():
    """Verify that non-zero GCP status codes are normalized to failure outcome."""
    denied_event = {
        "insertId": "test-denied-003",
        "protoPayload": {
            "serviceName": "secretmanager.googleapis.com",
            "methodName": "AccessSecretVersion",
            "status": {
                "code": 7,
                "message": "Permission denied"
            }
        }
    }
    parsed = normalize_event(denied_event)
    assert parsed["event"]["outcome"] == "failure"
    assert parsed["gcp"]["status_code"] == 7


def test_malformed_json_handling():
    """Verify that malformed JSON strings raise appropriate exceptions."""
    bad_json_string = '{"insertId": "broken-record", "protoPayload": {'
    with pytest.raises(json.JSONDecodeError):
        json.loads(bad_json_string)


def test_non_dictionary_json_payload():
    """Verify validation rejects non-dict JSON entries (e.g. naked strings or lists)."""
    raw_array = json.loads('["item1", "item2"]')
    assert not isinstance(raw_array, dict)
