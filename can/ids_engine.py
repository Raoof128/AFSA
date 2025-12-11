"""CAN Intrusion Detection System with multiple detection strategies."""

from __future__ import annotations

import json
import logging
import statistics
from collections import Counter
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

import numpy as np
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.metrics import classification_report
from sklearn.model_selection import train_test_split
from sklearn.svm import OneClassSVM

from can.simulator import CANFrame

logger = logging.getLogger(__name__)
logging.basicConfig(level=logging.INFO)


class RuleBasedIDS:
    """Rule-based IDS detecting invalid IDs, DLC, and frequency anomalies."""

    def __init__(self, valid_ids: Iterable[int] | None = None, max_dlc: int = 8):
        self.valid_ids = set(valid_ids) if valid_ids else set()
        self.max_dlc = max_dlc

    def detect(self, frames: List[CANFrame]) -> List[Tuple[CANFrame, str]]:
        alerts: List[Tuple[CANFrame, str]] = []
        id_counts = Counter(frame.message_id for frame in frames)
        avg_frequency = statistics.mean(id_counts.values()) if id_counts else 0
        for frame in frames:
            if self.valid_ids and frame.message_id not in self.valid_ids:
                alerts.append((frame, "invalid-id"))
            if frame.dlc > self.max_dlc:
                alerts.append((frame, "invalid-dlc"))
            if avg_frequency and id_counts[frame.message_id] > avg_frequency * 3:
                alerts.append((frame, "frequency-spike"))
        return alerts


class StatisticalIDS:
    """Statistical IDS using z-score and entropy heuristics."""

    def __init__(self, z_threshold: float = 3.0):
        self.z_threshold = z_threshold

    def detect(self, frames: List[CANFrame]) -> List[Tuple[CANFrame, str]]:
        alerts: List[Tuple[CANFrame, str]] = []
        if not frames:
            return alerts
        payload_lengths = [len(frame.data) for frame in frames]
        length_mean = statistics.mean(payload_lengths)
        length_std = statistics.pstdev(payload_lengths) or 1
        for frame in frames:
            z = abs(len(frame.data) - length_mean) / length_std
            if z > self.z_threshold:
                alerts.append((frame, "payload-length-zscore"))
        return alerts


class MachineLearningIDS:
    """Combines IsolationForest, One-Class SVM, and RandomForest for classification."""

    def __init__(self) -> None:
        self.isolation = IsolationForest(contamination=0.05, random_state=42)
        self.ocsvm = OneClassSVM(nu=0.05, gamma="scale")
        self.supervised = RandomForestClassifier(n_estimators=50, random_state=42)
        self.trained = False

    @staticmethod
    def _frame_to_features(frame: CANFrame) -> List[float]:
        """Convert a frame to a numeric feature vector for ML models."""
        return [frame.message_id & 0x7FF, frame.dlc, sum(frame.data), len(frame.data)]

    def fit_unsupervised(self, frames: List[CANFrame]) -> None:
        data = np.array([self._frame_to_features(f) for f in frames])
        self.isolation.fit(data)
        self.ocsvm.fit(data)

    def fit_supervised(self, frames: List[CANFrame]) -> None:
        X = np.array([self._frame_to_features(f) for f in frames])
        y = np.array([1 if f.label == "normal" else 0 for f in frames])
        if len(set(y)) <= 1:
            logger.warning("Supervised training skipped due to single-class dataset")
            return

        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
        self.supervised.fit(X_train, y_train)
        y_pred = self.supervised.predict(X_test)
        report = classification_report(y_test, y_pred, output_dict=True)
        logger.info(
            "Supervised model report: precision %.2f recall %.2f",
            report["weighted avg"]["precision"],
            report["weighted avg"]["recall"],
        )
        self.trained = True

    def detect(self, frames: List[CANFrame]) -> List[Tuple[CANFrame, str]]:
        alerts: List[Tuple[CANFrame, str]] = []
        if not frames:
            return alerts
        features = np.array([self._frame_to_features(f) for f in frames])
        isolation_scores = self.isolation.decision_function(features)
        svm_scores = self.ocsvm.decision_function(features)
        for frame, iso, svm in zip(frames, isolation_scores, svm_scores):
            if iso < 0 or svm < 0:
                alerts.append((frame, "ml-unsupervised-anomaly"))
        if self.trained:
            preds = self.supervised.predict(features)
            for frame, pred in zip(frames, preds):
                if pred == 0:
                    alerts.append((frame, "ml-supervised-malicious"))
        return alerts


def run_ids(frames: List[CANFrame], output_dir: Path) -> Dict[str, object]:
    """Execute all IDS stages and persist alert artifacts."""

    if not frames:
        raise ValueError("Frames list cannot be empty for IDS execution")

    output_dir.mkdir(parents=True, exist_ok=True)
    rule_ids = RuleBasedIDS(valid_ids=None)
    stat_ids = StatisticalIDS()
    ml_ids = MachineLearningIDS()
    ml_ids.fit_unsupervised(frames)
    ml_ids.fit_supervised(frames)

    alerts: List[Tuple[CANFrame, str]] = []
    alerts.extend(rule_ids.detect(frames))
    alerts.extend(stat_ids.detect(frames))
    alerts.extend(ml_ids.detect(frames))

    alerts_json = [{"frame": frame.to_dict(), "reason": reason} for frame, reason in alerts]
    alerts_path = output_dir / "intrusion_alerts.json"
    try:
        alerts_path.write_text(json.dumps(alerts_json, indent=2))
    except OSError as exc:
        logger.error("Unable to persist alert JSON: %s", exc)
        raise

    features = np.array([ml_ids._frame_to_features(f) for f in frames])
    anomaly_scores = np.array(list(ml_ids.isolation.decision_function(features)))
    scores_path = output_dir / "anomaly_scores.npy"
    try:
        np.save(scores_path, anomaly_scores)
    except OSError as exc:
        logger.error("Unable to save anomaly scores: %s", exc)
        raise

    labels_path = output_dir / "label_predictions.csv"
    try:
        labels_path.write_text(
            "message_id,dlc,label\n"
            + "\n".join(f"{f.message_id},{f.dlc},{f.label}" for f in frames)
        )
    except OSError as exc:
        logger.error("Unable to save label predictions: %s", exc)
        raise

    logger.info("IDS produced %d alerts", len(alerts))
    return {
        "alerts": alerts_json,
        "anomaly_scores_path": str(scores_path),
        "alerts_path": str(alerts_path),
        "labels_path": str(labels_path),
    }
