# Security Policy & Educational Safety Guidelines

## Educational Context and Scope

This repository is designed for **instructional demonstrations, DevSecOps hands-on workshops, cloud security training, and educational lab simulations**.

The lab provides two architectural modes:
1. **Mode A (Default - Local Simulation)**: Uses synthetically generated, non-sensitive JSONL audit logs processed by a local containerized OpenSearch cluster. No active connection to GCP or live credentials are required.
2. **Mode B (Optional Real Integration)**: Ingests telemetry from an active Google Cloud Platform project using Cloud Logging and Pub/Sub.

---

## Defensive Security Mandate

* **Defensive Focus**: All materials, detection rules, and exercises in this repository are designed strictly for detection engineering, security monitoring, threat hunting, and incident response education.
* **Synthetic Data Guarantee**: All sample logs provided in `sample-data/` contain fictional project IDs (`demo-student-project`), RFC 5737 documentation IP addresses (`198.51.100.0/24`, `203.0.113.0/24`), and synthetic principal emails (`compromised-admin@example.com`). No real cloud infrastructure or identities are targeted.
* **No Unauthorized Changes**: When testing against real GCP environments (Mode B), all actions must be performed in an isolated sandbox project with explicit organizational authorization.

---

## Local Container Security & Limitations

In local learning mode (Mode A):
* `plugins.security.disabled=true` is used by default in `compose.yaml` to minimize setup barriers (avoiding TLS certificate generation errors, basic authentication lockouts, and self-signed certificate rejections for beginning students).
* **CRITICAL**: Disabling the security plugin is **UNACCEPTABLE FOR PRODUCTION DEPLOYMENTS**.
* For production deployments, you must:
  1. Enable the OpenSearch Security Plugin (`plugins.security.disabled=false`).
  2. Configure strong TLS 1.3 certificates for transport (port 9300) and REST (port 9200) communication.
  3. Enforce strict Role-Based Access Control (RBAC) and integrate with an Identity Provider (LDAP, SAML, or OIDC).
  4. Restrict network listeners to private VPC interfaces behind an authenticated reverse proxy or API gateway.

---

## Secrets Management

* **Zero Secret Commitment**: Never commit `.env` files, Service Account JSON keys, GCP OAuth tokens, or OpenSearch administrative passwords to this repository.
* The `.gitignore` is configured to ignore `.env`, `*.secret`, `*.key`, and `*.pem` files.
* If a secret is accidentally committed during lab exercises, immediately revoke it in the GCP Console under **IAM & Admin > Service Accounts > Keys** or change the associated credential.

---

## Vulnerability Reporting

If you discover a security vulnerability or security misconfiguration in this project that compromises host environments or exposes sensitive data:

1. **Do not open a public GitHub issue.**
2. Send a security report to the repository maintainers with:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Proposed remediation
3. Maintainers will review the submission and provide a fix within a responsible disclosure timeframe.
