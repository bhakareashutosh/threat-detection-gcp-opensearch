# Contributing Guidelines

Thank you for your interest in improving this educational lab on **Threat Detection on GCP Audit Logs with OpenSearch Security Analytics**!

We welcome contributions from educators, students, security engineers, and developers.

---

## Code of Conduct

* Be respectful, inclusive, and collaborative.
* Treat student questions with patience and constructive guidance.
* Maintain a defensive, educational posture: exploit-only content or weaponized tooling will not be accepted.

---

## How You Can Contribute

1. **Detection Engineering**: Add new Sigma rules in `detection-rules/custom-rules/` for realistic GCP attack scenarios (e.g., Cloud Storage bucket public exposure, Cloud Build backdoor, VPC Flow Log tampering).
2. **Synthetic Telemetry**: Improve sample datasets in `sample-data/` to model complex multi-stage attack narratives.
3. **Lab Scenarios**: Suggest or write new student exercises in `exercises/`.
4. **Platform Compatibility**: Improve scripts for various container environments (Podman on Linux, WSL2, Docker on macOS/Windows).
5. **Documentation**: Clarify concepts, fix typos, and expand troubleshooting tips in `docs/`.

---

## Development Workflow

1. Fork the repository and clone your fork:
   ```bash
   git clone https://github.com/<your-username>/threat-detection-gcp-opensearch.git
   cd threat-detection-gcp-opensearch
   ```
2. Create a feature branch:
   ```bash
   git checkout -b feature/new-gcp-detection
   ```
3. Set up the local environment:
   ```bash
   cp .env.example .env
   make setup
   ```
4. Run tests before submitting:
   ```bash
   make test
   ```
5. Commit your changes with clear, descriptive commit messages:
   ```bash
   git commit -m "feat(detection): add Sigma rule for GCP Cloud Storage ACL public exposure"
   ```
6. Push to your branch and open a Pull Request.

---

## Guidelines for New Detection Rules

When adding a new custom rule:
* Place the JSON definition in `detection-rules/custom-rules/`.
* Provide a corresponding synthetic event in `sample-data/suspicious-events.jsonl`.
* Include a unit/integration test in `tests/test_detection_scenarios.py` verifying that the rule successfully triggers against the synthetic event.
* Document the threat scenario, MITRE ATT&CK mapping, potential false positives, and triage steps in `docs/detection-rules.md`.

---

## Submitting Pull Requests

* Ensure all automated tests (`make test`) pass.
* Verify documentation formatting and relative links.
* Provide a clear PR description explaining what was changed and why.
