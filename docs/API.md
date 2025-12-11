# API Reference

Base URL defaults to `http://localhost:8000` when running with `uvicorn backend.main:app`. All endpoints operate on synthetic data only.

## GET /health
- **Description:** Liveness probe
- **Response:** `{ "status": "ok" }`

## POST /analyze_firmware
- **Body:** `{ "path": "path/to/firmware" }`
- **Success (200):** firmware report JSON with entropy metrics, crypto references, credential hints, partition offsets, and output artifact paths.
- **Errors:** `404` if the firmware path does not exist, `500` on processing errors.

## POST /scan_vulnerabilities
- **Body:** `{ "extracted_fs": "path/to/extracted_fs" }`
- **Success (200):** `{ "findings": [...], "scores": {...} }`
- **Errors:** `404` if the path is missing, `500` on write/processing failures.

## POST /simulate_can
- **Body:** `{ "traffic_profile": "optional" }`
- **Success (200):** `{ "frames": [ {"message_id": ..., "dlc": ..., "data": [...], "timestamp": ..., "label": ...}, ... ] }`

## POST /run_ids
- **Body:** `{ "traffic_profile": "optional" }`
- **Success (200):** alert metadata plus artifact paths: `{ "alerts": [...], "anomaly_scores_path": "...", "alerts_path": "...", "labels_path": "..." }`
- **Errors:** `400` on empty traffic, `500` on processing errors.

## GET /dashboard
- **Description:** Provides a pointer to the static dashboard assets within `dashboard/`.
