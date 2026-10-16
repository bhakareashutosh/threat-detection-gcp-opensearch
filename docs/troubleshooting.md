# Troubleshooting Guide: Threat Detection Lab

This guide contains a comprehensive diagnostic and resolution matrix covering common issues encountered across containerization, ingestion, field mappings, detector execution, and student environments.

---

## 1. Quick Diagnostic Triage

When encountering any issue, run these diagnostic checks in sequence:

```bash
# 1. Check container runtime status
podman ps -a
# Or: docker ps -a

# 2. Check OpenSearch container logs
podman logs --tail 50 opensearch-node

# 3. Test cluster health endpoint directly
curl -s http://localhost:9200/_cluster/health

# 4. Run automated lab health check
make health-check
```

---

## 2. Troubleshooting Matrix

| Symptom | Likely Cause | Diagnostic Command | Fix | Verification |
| :--- | :--- | :--- | :--- | :--- |
| **Container exits immediately with code 137 or OutOfMemoryError** | Insufficient memory allocated to container runtime or JVM heap | `podman logs opensearch-node \| grep -i "OutOfMemory"` | Increase host/WSL RAM to at least 4GB. Set `OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g` in `.env` | Run `podman stats` to confirm JVM stays within memory limits |
| **Container exits on Linux/WSL with `max virtual memory areas vm.max_map_count [65530] is too low`** | Kernel mmap limit below OpenSearch minimum (262144) | `sysctl vm.max_map_count` | Run `sudo sysctl -w vm.max_map_count=262144` and add to `/etc/sysctl.conf` | `sysctl vm.max_map_count` outputs `262144` or higher |
| **Containers shut down after 15–30 seconds in WSL2 (Exit code 143)** | Windows WSL2 idle timeout shutting down subsystem when no foreground console is attached | `dmesg \| grep "systemd-shutdow"` | Run a persistent background keep-alive session in WSL (`sleep infinity &`) or configure `/etc/wsl.conf` | Containers remain in `Up` status in `podman ps` |
| **HTTP 401 Unauthorized or TLS Certificate verification failure on port 9200** | OpenSearch security plugin is active requiring HTTPS/Basic Auth | `curl -k -u admin:admin https://localhost:9200` | In local lab mode, verify `plugins.security.disabled=true` in `compose.yaml`. For production, pass `-k -u admin:<password>` | `curl http://localhost:9200` returns HTTP 200 without auth errors |
| **Field mapping error: `failed to parse field [protoPayload.status.code]`** | Mismatch between raw event format and index mapping (e.g. string vs integer) | `curl http://localhost:9200/gcp-audit-logs-demo/_mapping` | Ensure `gcp-audit-logs-mapping.json` is applied *before* ingesting logs. Delete index and re-ingest | Check mapping: `code` is type `integer` |
| **`make ingest` reports malformed records** | Input JSONL file contains corrupted JSON lines or non-object entries | Review terminal output of `scripts/ingest-sample-logs.sh` | Regenerate datasets with `make generate-logs`. Inspect line numbers flagged by the script | `make ingest` reports `0 malformed` |
| **Detector creation fails with `detector_type [gcp_audit_logs] is not supported`** | Attempting to use unregistered custom log type | `curl http://localhost:9200/_plugins/_security_analytics/logtype` | Use the built-in `others_application` log type (default) or register custom log type via `POST /_plugins/_security_analytics/logtype` | Detector creation returns HTTP 201 with detector ID |
| **Detector status active but Findings count is 0** | Detector evaluation interval has not elapsed yet, or field alias mapping is missing | `curl -X POST http://localhost:9200/_plugins/_security_analytics/findings/_search` | OpenSearch Security Analytics detectors run on a schedule (1 minute). Wait 60–90 seconds or verify field mappings using `scripts/configure_security_analytics.py` | Findings search returns hits matching synthetic threat events |
| **OpenSearch Dashboards shows red status / connection refused** | Dashboards started before OpenSearch was fully ready | `podman logs opensearch-dashboards` | Restart Dashboards container after OpenSearch status turns green | Visit `http://localhost:5601/api/status` and verify status is green/yellow |
| **Bulk indexing fails with HTTP 429 Too Many Requests** | Bulk payload size exceeds JVM queue capacity or system is thrashing | `podman logs opensearch-node \| grep "rejected execution"` | Ingest in smaller batches (default script uses ~16 events, well within capacity). Check system CPU load | Ingestion completes with all records acknowledged |

---

## 3. Step-by-Step Recovery Procedures

### Scenario A: Resetting Corrupted Indices
If an index was created with incorrect mappings:
```bash
# 1. Delete the contaminated index
curl -X DELETE "http://localhost:9200/gcp-audit-logs-demo"

# 2. Re-create index with clean mapping and ingest pipeline
make ingest

# 3. Verify document count
curl -s "http://localhost:9200/gcp-audit-logs-demo/_count"
```

### Scenario B: Full Environment Factory Reset
If containers or volumes enter an inconsistent state:
```bash
# 1. Tear down containers and destroy named volumes
make cleanup

# 2. Clear out any dangling containers
podman rm -f $(podman ps -aq) 2>/dev/null || true

# 3. Restart clean
make setup
make start
make ingest
make configure-detectors
make verify
```
