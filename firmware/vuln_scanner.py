"""
Firmware vulnerability scanner.
Analyses extracted firmware contents to identify insecure patterns.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Dict, List

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

WEAK_CRYPTO = {"md5", "sha1", "des", "rc4"}
DANGEROUS_APIS = {"strcpy", "sprintf", "gets", "strcat"}
BACKDOOR_KEYWORDS = {"backdoor", "debugmode", "test-user", "uart_debug"}
OUTDATED_TLS = {"openssl-1.0", "ssl3"}


def load_strings(extracted_path: Path) -> List[str]:
    """Load whitespace-delimited tokens from every file in a directory tree."""

    strings: List[str] = []
    for file in extracted_path.rglob("*"):
        if file.is_file():
            try:
                text = file.read_text(errors="ignore")
                strings.extend(text.split())
            except OSError as exc:
                logger.debug("Skipping unreadable file %s: %s", file, exc)
                continue
    return strings


def score_severity(findings: List[Dict[str, str]]) -> Dict[str, int]:
    """Convert finding severities into numeric scores for quick aggregation."""

    return {
        finding["id"]: {"high": 9, "medium": 5, "low": 2}[finding.get("severity", "low")]
        for finding in findings
    }


def scan_path(path: Path) -> List[Dict[str, str]]:
    """Run heuristic checks over an extracted filesystem path."""

    findings: List[Dict[str, str]] = []
    strings = load_strings(path)
    content_blob = " ".join(strings).lower()

    for weak in WEAK_CRYPTO:
        if weak in content_blob:
            findings.append(
                {
                    "id": f"weak-crypto-{weak}",
                    "description": f"Weak cryptography detected: {weak}",
                    "severity": "high" if weak in {"md5", "sha1"} else "medium",
                }
            )
    for api in DANGEROUS_APIS:
        if api in content_blob:
            findings.append(
                {
                    "id": f"dangerous-api-{api}",
                    "description": f"Unsafe C routine referenced: {api}",
                    "severity": "medium",
                }
            )
    for keyword in BACKDOOR_KEYWORDS:
        if keyword in content_blob:
            findings.append(
                {
                    "id": f"backdoor-{keyword}",
                    "description": f"Possible maintenance hook or backdoor: {keyword}",
                    "severity": "high",
                }
            )
    for tls in OUTDATED_TLS:
        if tls in content_blob:
            findings.append(
                {
                    "id": f"outdated-tls-{tls}",
                    "description": f"Outdated TLS stack reference: {tls}",
                    "severity": "medium",
                }
            )

    if "signature" not in content_blob and "secure_boot" not in content_blob:
        findings.append(
            {
                "id": "unsigned-boot",
                "description": "No signed boot chain artifacts detected (heuristic).",
                "severity": "medium",
            }
        )
    return findings


def scan_vulnerabilities(extracted_fs: Path, output_dir: Path) -> Dict[str, object]:
    """Scan an extracted filesystem manifest and persist findings and severity scores."""

    if not extracted_fs.exists():
        raise FileNotFoundError(f"Extracted filesystem not found: {extracted_fs}")

    output_dir.mkdir(parents=True, exist_ok=True)
    findings = scan_path(extracted_fs)
    severity_scores = score_severity(findings)
    findings_path = output_dir / "vuln_findings.json"
    scores_path = output_dir / "severity_scores.json"
    try:
        findings_path.write_text(json.dumps(findings, indent=2))
        scores_path.write_text(json.dumps(severity_scores, indent=2))
    except OSError as exc:
        logger.error("Unable to write vulnerability outputs: %s", exc)
        raise
    logger.info("Vulnerability scanning complete: %d findings", len(findings))
    return {"findings": findings, "scores": severity_scores}


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synthetic firmware vulnerability scanner")
    parser.add_argument("extracted_fs", type=Path, help="Path to extracted filesystem")
    parser.add_argument("--output", type=Path, default=Path("scan_output"))
    args = parser.parse_args()
    scan_vulnerabilities(args.extracted_fs, args.output)
