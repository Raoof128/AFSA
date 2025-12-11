# Architecture Overview

The system is composed of three main pillars:

1. **Firmware Pipeline**
   - `firmware/analyzer.py` computes entropy maps, extracts readable strings, detects crypto/backdoor hints, and records filesystem signatures. Outputs `firmware_report.json` and `entropy_map.png`, plus a synthetic `extracted_fs/manifest.json`.
   - `firmware/vuln_scanner.py` walks the extracted filesystem to flag weak cryptography, dangerous APIs, debug hooks, and unsigned boot heuristics, producing `vuln_findings.json` and `severity_scores.json`.

2. **CAN Security Pipeline**
   - `can/simulator.py` generates normal, injection, replay, and fuzzing frames with labels for training/testing.
   - `can/ids_engine.py` runs rule-based checks, statistical z-score tests, and machine-learning classifiers (IsolationForest, One-Class SVM, RandomForest). Artifacts include `intrusion_alerts.json`, `anomaly_scores.npy`, and `label_predictions.csv`.

3. **Interfaces**
   - `backend/main.py` exposes FastAPI endpoints to orchestrate firmware analysis and CAN IDS runs.
   - `dashboard/src/*` provides a React view for synthetic frames and alerts; connect via WebSocket in production.

All components are intentionally offline and synthetic to ensure safe experimentation.

## Data Flow
1. Firmware image is parsed by the analyzer, producing entropy plots and a synthetic extracted filesystem manifest.
2. Vulnerability scanner ingests the extracted manifest to score crypto/backdoor risk indicators.
3. CAN simulator produces labeled traffic; IDS ingests frames and emits alerts, scores, and label CSVs.
4. Backend orchestrates workflows and surfaces results to the dashboard.

## Deployment Notes
- FastAPI can run under Uvicorn or any ASGI server; set `OUTPUT_BASE` to an isolated path.
- Dashboard is static and may be served by CDN or reverse proxy; hook WebSocket streaming when integrating with live data.
- CI enforces linting and tests; pre-commit mirrors the same tools for local consistency.
