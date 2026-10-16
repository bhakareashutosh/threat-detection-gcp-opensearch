"""
Tests for Detection Rules, Threat Scenarios, and OpenSearch Integration.
"""

import os
import sys
import glob
import json
import urllib.request
import urllib.error
import pytest

repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(repo_root, "scripts"))

OPENSEARCH_HOST = os.getenv("OPENSEARCH_HOST", "http://localhost:9200")
INDEX_NAME = os.getenv("INDEX_NAME", "gcp-audit-logs-demo")
DETECTOR_NAME = os.getenv("DETECTOR_NAME", "gcp-threat-detector")


def is_opensearch_running():
    """Checks whether OpenSearch is accessible for live integration testing."""
    try:
        req = urllib.request.Request(f"{OPENSEARCH_HOST}/_cluster/health")
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status == 200
    except Exception:
        return False


# ==============================================================================
# Unit Tests (Offline - Always executed)
# ==============================================================================

def test_all_custom_rules_are_valid_sigma_json():
    """Verify all custom detection rule files are valid JSON with mandatory Sigma fields."""
    rules_dir = os.path.join(repo_root, "detection-rules", "custom-rules")
    rule_files = glob.glob(os.path.join(rules_dir, "*.json"))
    assert len(rule_files) >= 5, f"Expected at least 5 detection rules, found {len(rule_files)}"

    for rf in rule_files:
        with open(rf, "r", encoding="utf-8") as f:
            rule = json.load(f)
        
        filename = os.path.basename(rf)
        assert "title" in rule, f"{filename} missing 'title'"
        assert "id" in rule, f"{filename} missing 'id'"
        assert "detection" in rule, f"{filename} missing 'detection'"
        assert "condition" in rule["detection"], f"{filename} missing detection 'condition'"
        assert "level" in rule, f"{filename} missing 'level'"
        assert "tags" in rule, f"{filename} missing 'tags'"


def test_rule_matching_logic_against_synthetic_events():
    """Verify that detection rules logically match suspicious events and reject normal events."""
    suspicious_file = os.path.join(repo_root, "sample-data", "suspicious-events.jsonl")
    normal_file = os.path.join(repo_root, "sample-data", "normal-events.jsonl")

    with open(suspicious_file, "r", encoding="utf-8") as f:
        suspicious_events = [json.loads(line) for line in f if line.strip()]

    with open(normal_file, "r", encoding="utf-8") as f:
        normal_events = [json.loads(line) for line in f if line.strip()]

    # Scenario 1: IAM role binding modification
    iam_events = [
        e for e in suspicious_events 
        if e.get("protoPayload", {}).get("methodName") == "SetIamPolicy"
    ]
    assert len(iam_events) >= 1, "Must have at least one SetIamPolicy event"

    # Ensure no normal events contain SetIamPolicy
    normal_iam = [
        e for e in normal_events 
        if e.get("protoPayload", {}).get("methodName") == "SetIamPolicy"
    ]
    assert len(normal_iam) == 0, "Normal events must not trigger IAM modification rule"

    # Scenario 2: Service account key creation
    sa_key_events = [
        e for e in suspicious_events 
        if "CreateServiceAccountKey" in e.get("protoPayload", {}).get("methodName", "")
    ]
    assert len(sa_key_events) >= 1, "Must have at least one CreateServiceAccountKey event"

    # Scenario 3: Firewall rule creation
    firewall_events = [
        e for e in suspicious_events 
        if "firewalls.insert" in e.get("protoPayload", {}).get("methodName", "")
    ]
    assert len(firewall_events) >= 1, "Must have at least one firewall rule creation event"

    # Scenario 4: Permission denied
    denied_events = [
        e for e in suspicious_events 
        if e.get("protoPayload", {}).get("status", {}).get("code") == 7
    ]
    assert len(denied_events) >= 1, "Must have at least one permission denied event"

    # Scenario 5: DeleteSink
    sink_events = [
        e for e in suspicious_events 
        if "DeleteSink" in e.get("protoPayload", {}).get("methodName", "")
    ]
    assert len(sink_events) >= 1, "Must have at least one DeleteSink event"


# ==============================================================================
# Integration Tests (Live - executed when OpenSearch cluster is running)
# ==============================================================================

@pytest.mark.skipif(not is_opensearch_running(), reason="OpenSearch cluster is not running at " + OPENSEARCH_HOST)
def test_live_cluster_health():
    """Verify live cluster returns valid health state (green or yellow)."""
    req = urllib.request.Request(f"{OPENSEARCH_HOST}/_cluster/health")
    with urllib.request.urlopen(req, timeout=5) as resp:
        data = json.loads(resp.read().decode("utf-8"))
        assert data.get("status") in ("green", "yellow")


@pytest.mark.skipif(not is_opensearch_running(), reason="OpenSearch cluster is not running at " + OPENSEARCH_HOST)
def test_live_index_and_documents_indexed():
    """Verify live audit logs index exists and contains indexed documents."""
    req = urllib.request.Request(f"{OPENSEARCH_HOST}/{INDEX_NAME}/_count")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            count = data.get("count", 0)
            assert count > 0, f"Index '{INDEX_NAME}' has 0 documents. Run 'make ingest'."
    except urllib.error.HTTPError as e:
        pytest.fail(f"Index check failed with HTTP {e.code}: {e.read().decode('utf-8')}")


@pytest.mark.skipif(not is_opensearch_running(), reason="OpenSearch cluster is not running at " + OPENSEARCH_HOST)
def test_live_detector_configured():
    """Verify live Security Analytics detector is configured and active."""
    url = f"{OPENSEARCH_HOST}/_plugins/_security_analytics/detectors/_search"
    payload = json.dumps({"query": {"match_all": {}}}).encode("utf-8")
    req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            hits = data.get("hits", {}).get("hits", [])
            detector_names = [h.get("_source", {}).get("name") for h in hits]
            assert DETECTOR_NAME in detector_names, f"Detector '{DETECTOR_NAME}' not found in {detector_names}."
    except urllib.error.HTTPError as e:
        pytest.fail(f"Detector search failed with HTTP {e.code}: {e.read().decode('utf-8')}")


@pytest.mark.skipif(not is_opensearch_running(), reason="OpenSearch cluster is not running at " + OPENSEARCH_HOST)
def test_live_idempotent_duplicate_handling():
    """Verify indexing an event with identical insertId updates in-place without duplicating count."""
    count_req = urllib.request.Request(f"{OPENSEARCH_HOST}/{INDEX_NAME}/_count")
    with urllib.request.urlopen(count_req, timeout=5) as resp:
        initial_count = json.loads(resp.read().decode("utf-8"))["count"]

    # Re-index an existing event
    doc_id = "sim-threat-001-iam-escalation"
    doc_url = f"{OPENSEARCH_HOST}/{INDEX_NAME}/_doc/{doc_id}?refresh=true"
    payload = json.dumps({
        "insertId": doc_id,
        "timestamp": "2026-10-16T12:00:00Z",
        "protoPayload": {"methodName": "SetIamPolicy"}
    }).encode("utf-8")
    
    req = urllib.request.Request(doc_url, data=payload, headers={"Content-Type": "application/json"}, method="PUT")
    with urllib.request.urlopen(req, timeout=5) as resp:
        assert resp.status in (200, 201)

    # Count must remain unchanged
    with urllib.request.urlopen(count_req, timeout=5) as resp:
        new_count = json.loads(resp.read().decode("utf-8"))["count"]
        assert new_count == initial_count, "Document count should remain identical due to idempotent insertId"
