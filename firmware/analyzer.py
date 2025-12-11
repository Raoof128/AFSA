"""
Firmware Analyzer module.
Performs static analysis on firmware images (BIN/HEX/ELF) in a safe, synthetic manner.
"""

from __future__ import annotations

import json
import logging
import math
from pathlib import Path
from typing import Dict, Iterable, List

import matplotlib.pyplot as plt

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


def read_file_bytes(path: Path) -> bytes:
    """Read a file as bytes with error handling."""

    if not path.exists():
        raise FileNotFoundError(f"Firmware file does not exist: {path}")
    try:
        return path.read_bytes()
    except OSError as exc:
        logger.error("Failed to read file %s: %s", path, exc)
        raise


def compute_entropy(data: bytes, window: int = 2048) -> List[float]:
    """Compute Shannon entropy over sliding windows to identify compressed/encrypted regions."""

    if window <= 0:
        raise ValueError("Entropy window must be a positive integer")
    if not data:
        return []

    entropies: List[float] = []
    for i in range(0, len(data), window):
        chunk = data[i : i + window]
        freq = [0] * 256
        for byte in chunk:
            freq[byte] += 1
        chunk_len = len(chunk)
        entropy = 0.0
        for count in freq:
            if count == 0:
                continue
            p = count / chunk_len
            entropy -= p * math.log2(p)
        entropies.append(entropy)
    return entropies


def plot_entropy(entropies: List[float], output_path: Path) -> None:
    """Plot entropy map to visualize high-entropy segments."""

    plt.figure(figsize=(10, 4))
    plt.plot(entropies, marker="o", linewidth=1)
    plt.title("Entropy map (higher values suggest compression/encryption)")
    plt.xlabel("Window index")
    plt.ylabel("Shannon entropy")
    plt.tight_layout()
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        plt.savefig(output_path)
    finally:
        plt.close()


def extract_strings(data: bytes, min_len: int = 4) -> List[str]:
    """Extract human-readable ASCII strings."""

    if min_len <= 0:
        raise ValueError("Minimum string length must be positive")

    strings: List[str] = []
    current: List[str] = []
    for byte in data:
        if 32 <= byte < 127:
            current.append(chr(byte))
        else:
            if len(current) >= min_len:
                strings.append("".join(current))
            current = []
    if len(current) >= min_len:
        strings.append("".join(current))
    return strings


def detect_crypto_usage(strings: Iterable[str]) -> List[str]:
    """Detect references to common cryptographic primitives."""

    keywords = [
        "AES",
        "SHA1",
        "SHA256",
        "SHA512",
        "MD5",
        "RSA",
        "ChaCha20",
        "Curve25519",
    ]
    matches = {
        keyword for text in strings for keyword in keywords if keyword.lower() in text.lower()
    }
    return sorted(matches)


def detect_credentials(strings: Iterable[str]) -> List[str]:
    """
    Look for patterns that resemble credentials or debug traces.
    This is heuristic and intentionally conservative for safety.
    """

    findings: List[str] = []
    for text in strings:
        lowered = text.lower()
        if "password" in lowered or "passwd" in lowered:
            findings.append(text)
        if "debug" in lowered and "uart" in lowered:
            findings.append(text)
        if "api_key" in lowered:
            findings.append(text)
    return findings


def detect_partitions(data: bytes) -> List[Dict[str, int]]:
    """
    Detect common embedded filesystem signatures such as SquashFS and ext.
    Returns a list of offsets for transparency rather than performing real extraction.
    """

    signatures = {
        b"hsqs": "squashfs",
        b"\x53\xef": "ext",
    }
    findings: List[Dict[str, int]] = []
    for signature, name in signatures.items():
        start = 0
        while True:
            idx = data.find(signature, start)
            if idx == -1:
                break
            findings.append({"type": name, "offset": idx})
            start = idx + 1
    return findings


def save_extracted_fs(output_dir: Path, partitions: List[Dict[str, int]]) -> Path:
    """
    Create a synthetic extracted filesystem directory describing detected partitions.
    This is intentionally non-invasive and does not execute external tools.
    """

    extracted_path = output_dir / "extracted_fs"
    extracted_path.mkdir(parents=True, exist_ok=True)
    description = {
        "note": "Synthetic extraction manifest; no raw partitions are modified or mounted.",
        "partitions": partitions,
    }
    try:
        (extracted_path / "manifest.json").write_text(json.dumps(description, indent=2))
    except OSError as exc:
        logger.error("Unable to write manifest: %s", exc)
        raise
    return extracted_path


def analyze_firmware(file_path: Path, output_dir: Path) -> Dict[str, object]:
    """Run full firmware analysis workflow."""

    output_dir.mkdir(parents=True, exist_ok=True)
    data = read_file_bytes(file_path)
    entropies = compute_entropy(data)
    entropy_path = output_dir / "entropy_map.png"
    if entropies:
        plot_entropy(entropies, entropy_path)
    strings = extract_strings(data)
    crypto = detect_crypto_usage(strings)
    credentials = detect_credentials(strings)
    partitions = detect_partitions(data)
    extracted_fs_path = save_extracted_fs(output_dir, partitions)

    report = {
        "file": str(file_path),
        "size_bytes": len(data),
        "entropy": {
            "average": sum(entropies) / len(entropies) if entropies else 0,
            "max": max(entropies) if entropies else 0,
            "min": min(entropies) if entropies else 0,
            "windows": len(entropies),
        },
        "crypto_references": crypto,
        "potential_credentials": credentials,
        "partition_hits": partitions,
        "strings_sample": strings[:50],
        "outputs": {
            "entropy_map": str(entropy_path),
            "extracted_fs": str(extracted_fs_path),
        },
    }
    report_path = output_dir / "firmware_report.json"
    try:
        report_path.write_text(json.dumps(report, indent=2))
    except OSError as exc:
        logger.error("Failed to write firmware report: %s", exc)
        raise
    logger.info("Firmware analysis complete for %s", file_path)
    return report


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Synthetic firmware analyzer")
    parser.add_argument("firmware", type=Path, help="Path to firmware image")
    parser.add_argument(
        "--output", type=Path, default=Path("analysis_output"), help="Output directory"
    )
    args = parser.parse_args()
    analyze_firmware(args.firmware, args.output)
