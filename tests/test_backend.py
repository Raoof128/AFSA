"""Integration tests for FastAPI endpoints using synthetic artifacts."""

from __future__ import annotations

from importlib import reload
from pathlib import Path

from fastapi.testclient import TestClient

import backend.main as main_module


def test_health_endpoint() -> None:
    client = TestClient(main_module.app)
    response = client.get("/health")
    assert response.status_code == 200
    assert response.json().get("status") == "ok"


def test_firmware_and_vuln_endpoints(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path))
    reload(main_module)
    client = TestClient(main_module.app)

    firmware_path = Path("tests/data/sample.hex").resolve()
    firmware_resp = client.post("/analyze_firmware", json={"path": str(firmware_path)})
    assert firmware_resp.status_code == 200
    report = firmware_resp.json()
    assert report["size_bytes"] > 0

    extracted_fs = Path(report["outputs"]["extracted_fs"])
    vuln_resp = client.post("/scan_vulnerabilities", json={"extracted_fs": str(extracted_fs)})
    assert vuln_resp.status_code == 200
    findings = vuln_resp.json()["findings"]
    assert isinstance(findings, list)


def test_ids_endpoint(tmp_path: Path, monkeypatch) -> None:
    monkeypatch.setenv("OUTPUT_BASE", str(tmp_path))
    reload(main_module)
    client = TestClient(main_module.app)

    resp = client.post("/run_ids", json={"traffic_profile": "synthetic"})
    assert resp.status_code == 200
    payload = resp.json()
    assert "alerts" in payload
    assert len(payload["alerts"]) >= 1
