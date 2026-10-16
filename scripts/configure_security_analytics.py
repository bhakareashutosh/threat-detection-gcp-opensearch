#!/usr/bin/env python3
"""
Configure OpenSearch Security Analytics for GCP Cloud Audit Logs.

Steps:
1. Verifies OpenSearch cluster and Security Analytics plugin readiness.
2. Configures field alias mappings for Security Analytics schema.
3. Loads custom Sigma detection rules into Security Analytics.
4. Creates or updates a Detector attached to the audit logs index.
5. Prints configuration status and detector ID.
"""

import os
import sys
import glob
import json
import argparse
import urllib.request
import urllib.error

def api_request(method, url, payload=None, timeout=15):
    """Utility function for OpenSearch REST API calls."""
    data = None
    headers = {"Content-Type": "application/json"}
    if payload is not None:
        data = json.dumps(payload).encode("utf-8")
    
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            content = resp.read().decode("utf-8")
            return resp.status, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        content = e.read().decode("utf-8")
        try:
            parsed = json.loads(content)
        except Exception:
            parsed = {"error": content}
        return e.code, parsed
    except Exception as e:
        return 0, {"error": str(e)}


def check_plugins(host):
    """Verifies that the Security Analytics plugin is loaded."""
    status, body = api_request("GET", f"{host.rstrip('/')}/_cat/plugins?format=json")
    if status != 200:
        print(f"[-] Could not query plugins: {body}")
        return False
    
    installed = [p.get("component") for p in body]
    has_sa = "opensearch-security-analytics" in installed
    if has_sa:
        print("[+] OpenSearch Security Analytics plugin is verified active.")
        return True
    else:
        print("[!] Warning: opensearch-security-analytics not found in installed plugins list.")
        return False


def setup_field_mappings(host, index_name, log_type="others_application"):
    """Maps index fields to Security Analytics rule attributes."""
    print(f"[*] Configuring Security Analytics field mappings for index '{index_name}'...")
    url = f"{host.rstrip('/')}/_plugins/_security_analytics/mappings"
    
    mapping_payload = {
        "index_name": index_name,
        "rule_topic": log_type,
        "partial": True,
        "alias_mappings": {
            "properties": {
                "gcp.method_name": {
                    "type": "alias",
                    "path": "protoPayload.methodName"
                },
                "gcp.service_name": {
                    "type": "alias",
                    "path": "protoPayload.serviceName"
                },
                "gcp.principal": {
                    "type": "alias",
                    "path": "protoPayload.authenticationInfo.principalEmail"
                },
                "gcp.caller_ip": {
                    "type": "alias",
                    "path": "protoPayload.requestMetadata.callerIp"
                },
                "gcp.status_code": {
                    "type": "alias",
                    "path": "protoPayload.status.code"
                }
            }
        }
    }
    
    status, resp = api_request("POST", url, mapping_payload)
    if status in (200, 201):
        print(f"[+] Field mappings registered successfully for {index_name}.")
        return True
    else:
        print(f"[*] Note on mappings registration ({status}): {resp.get('error', resp)}")
        return False


def register_rules(host, rules_dir, log_type="others_application"):
    """Reads custom Sigma JSON rules and uploads them to OpenSearch."""
    rule_files = glob.glob(os.path.join(rules_dir, "*.json"))
    if not rule_files:
        print(f"[!] No custom rules found in {rules_dir}")
        return []

    print(f"[*] Loading {len(rule_files)} custom detection rules...")
    registered_rule_ids = []

    # Get existing custom rules to avoid duplicate errors
    search_url = f"{host.rstrip('/')}/_plugins/_security_analytics/rules/_search?category={log_type}"
    status, search_resp = api_request("POST", search_url, {"query": {"match_all": {}}})
    existing_rules_by_title = {}
    if status == 200:
        for hit in search_resp.get("hits", {}).get("hits", []):
            rule_id = hit.get("_id")
            title = hit.get("_source", {}).get("title")
            if title:
                existing_rules_by_title[title] = rule_id

    for rfile in rule_files:
        with open(rfile, "r", encoding="utf-8") as f:
            rule_data = json.load(f)

        title = rule_data.get("title", os.path.basename(rfile))
        
        # If already exists, reuse rule ID
        if title in existing_rules_by_title:
            rule_id = existing_rules_by_title[title]
            print(f"    [*] Rule already exists: '{title}' (ID: {rule_id})")
            registered_rule_ids.append(rule_id)
            continue

        # Register new rule
        create_url = f"{host.rstrip('/')}/_plugins/_security_analytics/rules?category={log_type}"
        status, resp = api_request("POST", create_url, rule_data)
        if status in (200, 201):
            rule_id = resp.get("_id")
            print(f"    [+] Created rule: '{title}' -> ID: {rule_id}")
            registered_rule_ids.append(rule_id)
        else:
            print(f"    [-] Failed to create rule '{title}' ({status}): {resp.get('error', resp)}")

    return registered_rule_ids


def create_or_update_detector(host, detector_name, index_name, rule_ids, log_type="others_application"):
    """Creates a Security Analytics Detector linking index and custom rules."""
    print(f"[*] Checking for existing detector '{detector_name}'...")
    
    # Search existing detectors
    search_url = f"{host.rstrip('/')}/_plugins/_security_analytics/detectors/_search"
    status, search_resp = api_request("POST", search_url, {"query": {"match_phrase": {"detector.name": detector_name}}})
    
    existing_detector_id = None
    if status == 200:
        hits = search_resp.get("hits", {}).get("hits", [])
        for hit in hits:
            if hit.get("_source", {}).get("name") == detector_name:
                existing_detector_id = hit.get("_id")
                break

    detector_input = {
        "description": "Monitors GCP Cloud Audit Logs for privilege escalation, credential exfiltration, and defense evasion",
        "indices": [index_name],
        "custom_rules": [{"id": rid} for rid in rule_ids]
    }

    detector_payload = {
        "name": detector_name,
        "detector_type": log_type,
        "enabled": True,
        "schedule": {
            "period": {
                "interval": 1,
                "unit": "MINUTES"
            }
        },
        "inputs": [
            {
                "detector_input": detector_input
            }
        ],
        "triggers": [
            {
                "name": "gcp-high-severity-trigger",
                "severity": "1",
                "types": [log_type],
                "actions": []
            }
        ]
    }

    if existing_detector_id:
        print(f"[*] Updating existing detector '{detector_name}' (ID: {existing_detector_id})...")
        update_url = f"{host.rstrip('/')}/_plugins/_security_analytics/detectors/{existing_detector_id}"
        status, resp = api_request("PUT", update_url, detector_payload)
        if status == 200:
            print(f"[+] Detector updated successfully (ID: {existing_detector_id}).")
            return existing_detector_id
        else:
            print(f"[-] Failed to update detector ({status}): {resp.get('error', resp)}")
            return existing_detector_id
    else:
        print(f"[*] Creating new detector '{detector_name}'...")
        create_url = f"{host.rstrip('/')}/_plugins/_security_analytics/detectors"
        status, resp = api_request("POST", create_url, detector_payload)
        if status in (200, 201):
            detector_id = resp.get("_id")
            print(f"[+] Successfully created detector '{detector_name}' (ID: {detector_id}).")
            return detector_id
        else:
            print(f"[-] Failed to create detector ({status}): {resp.get('error', resp)}")
            return None


def main():
    parser = argparse.ArgumentParser(description="Configure OpenSearch Security Analytics for GCP Logs")
    parser.add_argument("--host", default=os.getenv("OPENSEARCH_HOST", "http://localhost:9200"),
                        help="OpenSearch host URL")
    parser.add_argument("--index", default=os.getenv("INDEX_NAME", "gcp-audit-logs-demo"),
                        help="Target index name")
    parser.add_argument("--detector-name", default=os.getenv("DETECTOR_NAME", "gcp-threat-detector"),
                        help="Security Analytics detector name")
    parser.add_argument("--log-type", default=os.getenv("DETECTOR_LOG_TYPE", "others_application"),
                        help="Security Analytics log category (default: others_application)")
    args = parser.parse_args()

    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    rules_dir = os.path.join(repo_root, "detection-rules", "custom-rules")

    print("================================================================================")
    print(" OpenSearch Security Analytics Configuration")
    print("================================================================================")
    print(f"Target Cluster: {args.host}")
    print(f"Target Index:   {args.index}")
    print(f"Detector Name:  {args.detector_name}")
    print(f"Log Category:   {args.log_type}")
    print(f"Rules Dir:      {rules_dir}")

    # 1. Plugin verification
    check_plugins(args.host)

    # 2. Field mappings
    setup_field_mappings(args.host, args.index, args.log_type)

    # 3. Register custom Sigma rules
    rule_ids = register_rules(args.host, rules_dir, args.log_type)
    if not rule_ids:
        print("[!] No rules were registered. Cannot proceed with detector creation.")
        sys.exit(1)

    # 4. Create / update detector
    detector_id = create_or_update_detector(args.host, args.detector_name, args.index, rule_ids, args.log_type)
    if detector_id:
        print("================================================================================")
        print(f"[+] Security Analytics successfully initialized!")
        print(f"    Detector ID:       {detector_id}")
        print(f"    Active Rules:      {len(rule_ids)}")
        print(f"    Monitoring Index:  {args.index}")
        print(f"    Schedule Interval: 1 minute")
        print("================================================================================")
    else:
        print("[-] Security Analytics configuration completed with warnings.")
        sys.exit(1)


if __name__ == "__main__":
    main()
