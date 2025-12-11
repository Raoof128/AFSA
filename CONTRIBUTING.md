# Contributing Guide

Thank you for contributing to the synthetic Automotive Firmware Security Analyzer! All contributions must preserve the offline, demo-only nature of this project.

## Getting Started
1. Fork the repository and create a feature branch.
2. Install dependencies with `pip install -r requirements.txt` (use a virtual environment).
3. Enable pre-commit hooks with `pre-commit install` to match CI formatting.
4. Run `scripts/lint.sh` and `pytest` before opening a pull request.

## Development Workflow
- Prefer small, focused commits with clear messages.
- Include unit tests for new functionality and update documentation as needed.
- Add type hints and docstrings for all public functions/classes; avoid unused code paths.
- Validate inputs and log meaningful security-relevant events.

## Coding Standards
- Follow Black formatting, isort imports, and Ruff linting (configured in `pyproject.toml`).
- Avoid hard-coded secrets or real vehicle identifiers; use synthetic data only.
- Include error handling around I/O or network interactions; never catch broad exceptions without re-raising or logging.

## Security & Safety
- Only synthetic CAN and firmware samples are allowed.
- Do not include exploit code or hardware flashing utilities.
- Report vulnerabilities responsibly via the security policy.
- Avoid adding dependencies without reviewing licenses and security posture.

## Pull Requests
- Describe the change, rationale, and testing performed.
- Note any deviations from the safety guardrails.
- Expect CI to run linting and tests; fixes should keep CI green.

## Communication
Use clear commit messages and provide reproduction steps for bugs. If adding new detection logic, include rationale and test vectors.
