# Prerequisites: Threat Detection on GCP Audit Logs Lab

This document outlines the hardware, operating system, and software prerequisites required to run this lab successfully.

---

## 1. Hardware Requirements

| Resource | Minimum Requirement | Recommended Specification |
| :--- | :--- | :--- |
| **Processor** | 2 CPU Cores (x86_64 or ARM64) | 4+ CPU Cores |
| **Memory (RAM)** | 4 GB Total Host RAM | 8 GB - 16 GB Host RAM |
| **OpenSearch Heap** | 1 GB JVM Heap (`-Xms1g -Xmx1g`) | 1 GB - 2 GB JVM Heap |
| **Storage (Disk)** | 10 GB Free Storage Space | 25 GB SSD Storage |

---

## 2. Operating System Support

* **Linux**: Ubuntu 20.04+, Debian 11+, Fedora 38+, RHEL / Rocky Linux 9+.
* **macOS**: macOS Monterey (12+) or newer on Intel or Apple Silicon (M1/M2/M3/M4).
* **Windows**: Windows 10 / 11 (64-bit) with **WSL2** (Windows Subsystem for Linux 2) running Ubuntu or Debian.

---

## 3. Required Software Tools

### Container Runtime (Podman Preferred)
* **Podman**: Version 4.0 or newer.
  * Verify: `podman --version`
  * Alternative: **Docker** version 20.10+ (`docker --version`).
* **Compose Tool**: `podman-compose` version 1.0+ or `docker compose` plugin.
  * Verify: `podman-compose --version` or `docker compose version`

### Python Environment
* **Python**: Version 3.9 or newer.
  * Verify: `python3 --version` or `python --version`
* **Python Packages** (for tests and utilities):
  * `requests`, `pytest`, `pyyaml`
  * Install via:
    ```bash
    pip3 install -r - <<EOF
    requests>=2.28.0
    pytest>=7.0.0
    pyyaml>=6.0
    EOF
    ```

### Command-Line Utilities
* **curl**: Used by health check and verification scripts (`curl --version`).
* **GNU Make**: Used to execute convenient `make` targets (`make --version`). On systems without Make, the underlying bash scripts in `scripts/` can be run directly.

---

## 4. Kernel Configuration (Linux / WSL2 Only)

OpenSearch uses an `mmapfs` directory by default to store its indices. The default operating system limits on mmap counts may be too low, which can result in out-of-memory exceptions.

Check your current `vm.max_map_count`:
```bash
sysctl vm.max_map_count
```

If the value is below `262144`, adjust it:
```bash
sudo sysctl -w vm.max_map_count=262144
```

To make this change permanent across system reboots, add the following line to `/etc/sysctl.conf`:
```ini
vm.max_map_count=262144
```

---

## 5. Verification Checklist

Run these commands in your terminal to verify your workstation is ready:

```bash
# Check container runtime
podman --version || docker --version

# Check compose tool
podman-compose --version || docker-compose --version || docker compose version

# Check Python
python3 --version || python --version

# Check Curl
curl --version
```
