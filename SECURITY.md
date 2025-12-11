# Security Policy

## Scope
This project is strictly synthetic and educational. No real vehicle interaction, flashing, or exploitation is permitted.

## Supported Versions
Security updates are applied on a best-effort basis. Always run the latest main branch and pinned dependencies (`requirements.txt`).

## Reporting a Vulnerability
- Email `security@example.com` with a detailed report, including reproduction steps and impacted components.
- Do not share exploit code publicly; this repo is for educational use only.
- We will acknowledge receipt within 5 business days and provide a remediation plan when applicable.

## Safe Usage Guidelines
- Use only with synthetic firmware/CAN samples.
- Do not connect to real vehicles or production networks.
- Review heuristic findings before acting on them; false positives are possible.
- Keep outputs confined to the `OUTPUT_BASE` directory to avoid unintended file writes.

## Dependency Management
- Dependencies are pinned for reproducibility. Use `pip install -r requirements.txt`.
- Before adding dependencies, check licenses and known CVEs.
- Run `scripts/lint.sh` and `pytest` locally to validate changes.
