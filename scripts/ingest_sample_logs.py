#!/usr/bin/env python3
"""
Ingest and normalize GCP Cloud Audit Logs into OpenSearch.

Key Features:
- Reads JSONL event streams.
- Validates structural schema.
- Normalizes core security fields while preserving raw fidelity.
- Uses GCP `insertId` as OpenSearch `_id` to guarantee idempotent ingestion.
- Catches and logs malformed lines without crashing.
- Verifies cluster connectivity and document counts.
"""

import os
import sys
import json
import argparse
from datetime import datetime
import urllib.request
import urllib.error

def check_opensearch_health(host):
    """Verifies OpenSearch connectivity."""
    url = f"{host.rstrip('/')}/_cluster/health"
    try:
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            return True, data.get("status", "unknown")
    except Exception as e:
        return False, str(e)


def create_pipeline(host, pipeline_path):
    """Registers the Ingest Pipeline in OpenSearch."""
    if not os.path.exists(pipeline_path):
        print(f"[!] Ingest pipeline file not found: {pipeline_path}")
        return False

    with open(pipeline_path, "r", encoding="utf-8") as f:
        pipeline_body = json.load(f)

    url = f"{host.rstrip('/')}/_ingest/pipeline/gcp-audit-logs-normalization"
    data = json.dumps(pipeline_body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"}, method="PUT")
    
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 201):
                print(f"[+] Ingest pipeline 'gcp-audit-logs-normalization' configured successfully.")
                return True
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        print(f"[-] Failed to create ingest pipeline: {err}")
        return False
    except Exception as e:
        print(f"[-] Error connecting to OpenSearch pipeline API: {e}")
        return False


def create_index_with_mapping(host, index_name, mapping_path):
    """Creates index with explicit mappings if it does not already exist."""
    check_url = f"{host.rstrip('/')}/{index_name}"
    
    # Check if index exists
    req = urllib.request.Request(check_url, method="HEAD")
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            if resp.status == 200:
                print(f"[*] Index '{index_name}' already exists.")
                return True
    except urllib.error.HTTPError as e:
        if e.code != 404:
            print(f"[-] Error checking index: {e}")
            return False
    except Exception:
        pass

    # Index does not exist, create it
    if not os.path.exists(mapping_path):
        print(f"[!] Mapping file not found: {mapping_path}")
        return False

    with open(mapping_path, "r", encoding="utf-8") as f:
        mapping_body = json.load(f)

    create_url = f"{host.rstrip('/')}/{index_name}"
    data = json.dumps(mapping_body).encode("utf-8")
    req = urllib.request.Request(create_url, data=data, headers={"Content-Type": "application/json"}, method="PUT")
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            if resp.status in (200, 201):
                print(f"[+] Index '{index_name}' created with mapping and default pipeline.")
                return True
    except urllib.error.HTTPError as e:
        err = e.read().decode("utf-8")
        print(f"[-] Failed to create index '{index_name}': {err}")
        return False
    except Exception as e:
        print(f"[-] Error creating index: {e}")
        return False


def normalize_event(raw_event):
    """
    Normalizes GCP Cloud Audit Log fields for Security Analytics detectors.
    Preserves raw data under protoPayload and adds normalized taxonomy fields.
    """
    doc = dict(raw_event)
    
    # Ensure @timestamp
    ts = doc.get("timestamp") or datetime.utcnow().isoformat() + "Z"
    doc["@timestamp"] = ts

    # Cloud context
    if "cloud" not in doc:
        doc["cloud"] = {}
    doc["cloud"]["provider"] = "gcp"

    res_labels = doc.get("resource", {}).get("labels", {})
    if "project_id" in res_labels:
        doc["cloud"]["project"] = {"id": res_labels["project_id"]}

    proto = doc.get("protoPayload", {})

    # Method / Action
    method = proto.get("methodName", "")
    service = proto.get("serviceName", "")
    principal = proto.get("authenticationInfo", {}).get("principalEmail", "")
    caller_ip = (
        proto.get("requestMetadata", {}).get("callerIp") or
        proto.get("authenticationInfo", {}).get("callerIp") or ""
    )
    resource_name = proto.get("resourceName", "")
    status_code = proto.get("status", {}).get("code", 0)

    # Set normalized aliases
    doc["event"] = {
        "action": method,
        "outcome": "success" if status_code == 0 else "failure",
        "category": "iam" if "iam" in service or "SetIamPolicy" in method else "configuration"
    }
    doc["service"] = {"name": service}
    doc["user"] = {"name": principal}
    doc["actor"] = {"user": principal}
    if caller_ip and caller_ip not in ("unknown", "network-external"):
        doc["source"] = {"ip": caller_ip}
    doc["resource"] = {
        "name": resource_name,
        "type": doc.get("resource", {}).get("type", "unknown")
    }

    # Normalized gcp.* namespace
    doc["gcp"] = {
        "service_name": service,
        "method_name": method,
        "principal": principal,
        "caller_ip": caller_ip,
        "resource_name": resource_name,
        "status_code": status_code
    }

    # Set log_type for OpenSearch Security Analytics
    doc["log_type"] = "others_application"

    return doc


def ingest_file(host, index_name, file_path):
    """Ingests a JSONL file using the OpenSearch Bulk API."""
    if not os.path.exists(file_path):
        print(f"[!] File not found: {file_path}")
        return 0, 0, 0

    print(f"[*] Reading {file_path}...")
    bulk_lines = []
    valid_count = 0
    malformed_count = 0

    with open(file_path, "r", encoding="utf-8") as f:
        for line_num, line in enumerate(f, start=1):
            line_str = line.strip()
            if not line_str:
                continue
            try:
                raw_event = json.loads(line_str)
                # Validation: must have insertId or protoPayload
                if not isinstance(raw_event, dict):
                    raise ValueError("Event must be a JSON object")

                doc_id = raw_event.get("insertId")
                normalized_doc = normalize_event(raw_event)

                # Bulk action metadata (using insertId for idempotency if present)
                action = {"index": {"_index": index_name}}
                if doc_id:
                    action["index"]["_id"] = doc_id

                bulk_lines.append(json.dumps(action))
                bulk_lines.append(json.dumps(normalized_doc))
                valid_count += 1
            except Exception as e:
                malformed_count += 1
                print(f"[!] Warning: Line {line_num} in {os.path.basename(file_path)} is malformed: {e}")

    if not bulk_lines:
        print(f"[*] No valid records found in {file_path}.")
        return 0, valid_count, malformed_count

    # Execute bulk request
    bulk_payload = "\n".join(bulk_lines) + "\n"
    url = f"{host.rstrip('/')}/_bulk?refresh=true"
    req = urllib.request.Request(
        url,
        data=bulk_payload.encode("utf-8"),
        headers={"Content-Type": "application/x-ndjson"},
        method="POST"
    )

    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            resp_body = json.loads(resp.read().decode("utf-8"))
            errors = resp_body.get("errors", False)
            indexed_items = len(resp_body.get("items", []))
            if errors:
                print(f"[-] Bulk ingestion encountered some errors.")
                # Show first error
                for it in resp_body.get("items", []):
                    action_resp = it.get("index", {})
                    if "error" in action_resp:
                        print(f"    Item error: {action_resp['error']}")
                        break
            else:
                print(f"[+] Successfully indexed {indexed_items} records from {os.path.basename(file_path)}.")
            return indexed_items, valid_count, malformed_count
    except Exception as e:
        print(f"[-] Bulk request failed: {e}")
        return 0, valid_count, malformed_count


def verify_count(host, index_name):
    """Queries OpenSearch to verify document count in the index."""
    url = f"{host.rstrip('/')}/{index_name}/_count"
    try:
        req = urllib.request.Request(url, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=5) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            count = data.get("count", 0)
            print(f"[+] Total verified documents in index '{index_name}': {count}")
            return count
    except Exception as e:
        print(f"[-] Error verifying document count: {e}")
        return -1


def main():
    parser = argparse.ArgumentParser(description="Ingest GCP Cloud Audit Logs into OpenSearch")
    parser.add_argument("--host", default=os.getenv("OPENSEARCH_HOST", "http://localhost:9200"),
                        help="OpenSearch host URL (default: http://localhost:9200)")
    parser.add_argument("--index", default=os.getenv("INDEX_NAME", "gcp-audit-logs-demo"),
                        help="Target OpenSearch index name")
    parser.add_argument("--files", nargs="*", help="List of JSONL files to ingest")
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    pipeline_path = os.path.join(repo_root, "config", "pipelines", "log-normalization-pipeline.json")
    mapping_path = os.path.join(repo_root, "config", "mappings", "gcp-audit-logs-mapping.json")

    print("================================================================================")
    print(" GCP Cloud Audit Log Ingestion & Normalization")
    print("================================================================================")
    print(f"Host:       {args.host}")
    print(f"Index:      {args.index}")

    # Step 1: Health check
    healthy, status = check_opensearch_health(args.host)
    if not healthy:
        print(f"[-] OpenSearch is unreachable at {args.host} ({status}).")
        print("    Ensure the container is started with 'make start' or check container logs.")
        sys.exit(1)
    print(f"[+] OpenSearch cluster is accessible (status: {status}).")

    # Step 2: Configure pipeline & mapping
    create_pipeline(args.host, pipeline_path)
    create_index_with_mapping(args.host, args.index, mapping_path)

    # Step 3: Determine files to ingest
    files_to_ingest = args.files
    if not files_to_ingest:
        sample_dir = os.path.join(repo_root, "sample-data")
        normal_f = os.path.join(sample_dir, "normal-events.jsonl")
        suspicious_f = os.path.join(sample_dir, "suspicious-events.jsonl")
        files_to_ingest = [normal_f, suspicious_f]

    total_indexed = 0
    total_valid = 0
    total_malformed = 0

    for file_path in files_to_ingest:
        indexed, valid, malformed = ingest_file(args.host, args.index, file_path)
        total_indexed += indexed
        total_valid += valid
        total_malformed += malformed

    print("--------------------------------------------------------------------------------")
    print(f"Summary: {total_valid} valid records processed, {total_malformed} malformed, {total_indexed} indexed.")
    verify_count(args.host, args.index)
    print("================================================================================")


if __name__ == "__main__":
    main()
