from pathlib import Path

from firmware.analyzer import analyze_firmware
from firmware.vuln_scanner import scan_vulnerabilities


def test_analyze_and_scan(tmp_path: Path) -> None:
    firmware_path = Path("tests/data/sample.hex")
    output_dir = tmp_path / "analysis"
    report = analyze_firmware(firmware_path, output_dir)
    assert report["size_bytes"] > 0
    assert (output_dir / "entropy_map.png").exists()
    assert (output_dir / "firmware_report.json").exists()

    scan_output = tmp_path / "scan"
    results = scan_vulnerabilities(output_dir / "extracted_fs", scan_output)
    assert "findings" in results
    assert (scan_output / "vuln_findings.json").exists()
