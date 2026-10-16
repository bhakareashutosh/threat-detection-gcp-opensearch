"""
Unit tests for log normalization rules and schema mapping consistency.
"""

import json
import os
import sys

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(repo_root, "scripts"))

from ingest_sample_logs import normalize_event

def test_pipeline_json_is_valid():
    """Verify that the OpenSearch Ingest Pipeline configuration is valid JSON."""
    pipeline_file = os.path.join(repo_root, "config", "pipelines", "log-normalization-pipeline.json")
    assert os.path.exists(pipeline_file), "Ingest pipeline file must exist"
    
    with open(pipeline_file, "r", encoding="utf-8") as f:
        pipeline = json.load(f)
    
    assert "description" in pipeline
    assert "processors" in pipeline
    assert isinstance(pipeline["processors"], list)
    assert len(pipeline["processors"]) > 0


def test_mapping_json_is_valid():
    """Verify that the OpenSearch Index Mapping configuration is valid JSON with required types."""
    mapping_file = os.path.join(repo_root, "config", "mappings", "gcp-audit-logs-mapping.json")
    assert os.path.exists(mapping_file), "Mapping file must exist"

    with open(mapping_file, "r", encoding="utf-8") as f:
        mapping = json.load(f)

    assert "mappings" in mapping
    props = mapping["mappings"]["properties"]
    assert props["@timestamp"]["type"] == "date"
    assert props["insertId"]["type"] == "keyword"
    assert props["protoPayload"]["properties"]["methodName"]["type"] == "keyword"
    assert props["protoPayload"]["properties"]["serviceName"]["type"] == "keyword"


def test_raw_payload_preservation():
    """Verify normalization preserves raw GCP protoPayload without losing nested structures."""
    raw = {
        "insertId": "preserve-test-01",
        "timestamp": "2026-10-16T10:30:00Z",
        "protoPayload": {
            "serviceName": "logging.googleapis.com",
            "methodName": "DeleteSink",
            "resourceName": "projects/demo-student-project/sinks/siem-export",
            "serviceData": {
                "customNestedField": "critical-data"
            }
        }
    }
    normalized = normalize_event(raw)
    assert normalized["protoPayload"]["serviceData"]["customNestedField"] == "critical-data"
    assert normalized["gcp"]["method_name"] == "DeleteSink"
    assert normalized["gcp"]["resource_name"] == "projects/demo-student-project/sinks/siem-export"


def test_security_analytics_log_type_tag():
    """Ensure normalized events have the log_type attribute for Security Analytics."""
    raw = {
        "insertId": "tag-test-01",
        "protoPayload": {"methodName": "SetIamPolicy"}
    }
    normalized = normalize_event(raw)
    assert normalized.get("log_type") == "others_application"
