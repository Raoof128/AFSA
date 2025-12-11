"""FastAPI backend exposing firmware analysis and CAN IDS endpoints."""

from __future__ import annotations

import logging
import os
from pathlib import Path
from typing import Any, Dict

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from can.ids_engine import run_ids
from can.simulator import generate_full_scenario
from firmware.analyzer import analyze_firmware
from firmware.vuln_scanner import scan_vulnerabilities

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)

OUTPUT_BASE = Path(os.getenv("OUTPUT_BASE", "outputs"))

app = FastAPI(title="Synthetic Automotive Security Suite", version="1.0.0")


class FirmwareRequest(BaseModel):
    path: str


class VulnerabilityRequest(BaseModel):
    extracted_fs: str


class IDsRequest(BaseModel):
    traffic_profile: str | None = None


@app.get("/health")
def health() -> Dict[str, str]:
    """Health probe used by monitors and tests."""
    return {"status": "ok"}


@app.post("/analyze_firmware")
def analyze(req: FirmwareRequest) -> Dict[str, Any]:
    """Run static firmware analysis and return the generated report."""
    firmware_path = Path(req.path)
    if not firmware_path.is_file():
        raise HTTPException(status_code=404, detail="Firmware not found")
    output = OUTPUT_BASE / "firmware"
    try:
        report = analyze_firmware(firmware_path, output)
    except OSError as exc:
        logger.error("Firmware analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail="Analysis failed") from exc
    return report


@app.post("/scan_vulnerabilities")
def scan(req: VulnerabilityRequest) -> Dict[str, Any]:
    """Execute the vulnerability scanner over an extracted filesystem."""
    fs_path = Path(req.extracted_fs)
    if not fs_path.exists():
        raise HTTPException(status_code=404, detail="Extracted filesystem not found")
    output = OUTPUT_BASE / "vulns"
    try:
        return scan_vulnerabilities(fs_path, output)
    except OSError as exc:
        logger.error("Vulnerability scan failed: %s", exc)
        raise HTTPException(status_code=500, detail="Scan failed") from exc


@app.post("/simulate_can")
def simulate(req: IDsRequest) -> Dict[str, Any]:
    """Generate a synthetic CAN scenario for downstream IDS processing."""
    frames = generate_full_scenario()
    return {"frames": [f.to_dict() for f in frames]}


@app.post("/run_ids")
def run(req: IDsRequest) -> Dict[str, Any]:
    """Run the full IDS stack on synthetic traffic and persist artifacts."""
    frames = generate_full_scenario()
    output = OUTPUT_BASE / "ids"
    try:
        return run_ids(frames, output)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    except OSError as exc:
        logger.error("IDS execution failed: %s", exc)
        raise HTTPException(status_code=500, detail="IDS execution failed") from exc


@app.get("/dashboard")
def dashboard() -> Dict[str, str]:
    """Provide a hint to the static dashboard assets served separately."""
    return {"message": "Dashboard served via frontend (static)."}
