"""
ML Engine Inference Server — FastAPI
Exposes REST endpoints consumed by other platform microservices.

Run: uvicorn serve:app --host 0.0.0.0 --port 8080 --reload
"""

from __future__ import annotations
import logging
import numpy as np
import pandas as pd
import time
from contextlib import asynccontextmanager
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

from models import MetricAnomalyDetector, LogSequenceDetector

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# ── Global model holders ──────────────────────────────────────
iso_detector: MetricAnomalyDetector | None = None
lstm_detector: LogSequenceDetector | None = None


@asynccontextmanager
async def lifespan(app: FastAPI):
    global iso_detector, lstm_detector
    logger.info("Loading models …")
    try:
        iso_detector = MetricAnomalyDetector.load("models/isolation_forest.pkl")
        logger.info("Isolation Forest loaded ✓")
    except Exception as e:
        logger.warning("Could not load Isolation Forest: %s", e)

    try:
        lstm_detector = LogSequenceDetector.load(
            model_path="models/lstm_autoencoder.keras",
            meta_path="models/lstm_meta.pkl",
        )
        logger.info("LSTM Autoencoder loaded ✓")
    except Exception as e:
        logger.warning("Could not load LSTM model: %s", e)

    yield  # server runs here

    logger.info("Shutting down ML Engine …")


app = FastAPI(
    title="Cloud Security ML Engine",
    version="1.0.0",
    description="Anomaly detection microservice for the cloud security platform",
    lifespan=lifespan,
)


# ── Request / Response Schemas ────────────────────────────────

class MetricRecord(BaseModel):
    cpu_usage: float
    memory_usage: float
    network_in_bytes: float
    network_out_bytes: float
    disk_read_iops: float
    disk_write_iops: float
    http_request_rate: float
    http_error_rate: float
    pod_restart_count: float
    latency_p95_ms: float


class MetricBatchRequest(BaseModel):
    records: list[MetricRecord]
    service_name: str = "unknown"
    namespace: str = "default"


class MetricPrediction(BaseModel):
    index: int
    is_anomaly: bool
    anomaly_score: float
    severity: str
    service_name: str
    namespace: str


class MetricBatchResponse(BaseModel):
    predictions: list[MetricPrediction]
    total_anomalies: int
    processing_time_ms: float


class LogSequenceRequest(BaseModel):
    """
    sequence: 2D array of shape [seq_len, n_features]
    Each row represents one log event as a feature vector.
    """
    sequence: list[list[float]]
    service_name: str = "unknown"
    namespace: str = "default"


class LogSequenceResponse(BaseModel):
    is_anomaly: bool
    reconstruction_error: float
    threshold: float
    severity: str
    service_name: str
    namespace: str
    processing_time_ms: float


# ── Severity helper ───────────────────────────────────────────

def score_to_severity(anomaly_score: float) -> str:
    """Convert raw Isolation Forest score to alert severity."""
    # Scores are negative; more negative = more anomalous
    if anomaly_score < -0.3:
        return "CRITICAL"
    elif anomaly_score < -0.2:
        return "HIGH"
    elif anomaly_score < -0.1:
        return "MEDIUM"
    return "LOW"


def error_to_severity(error: float, threshold: float) -> str:
    ratio = error / threshold if threshold > 0 else 1.0
    if ratio > 3.0:
        return "CRITICAL"
    elif ratio > 2.0:
        return "HIGH"
    elif ratio > 1.0:
        return "MEDIUM"
    return "LOW"


# ── Endpoints ─────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {
        "status": "ok",
        "iso_model_loaded": iso_detector is not None,
        "lstm_model_loaded": lstm_detector is not None,
    }


@app.post("/predict/metrics", response_model=MetricBatchResponse)
async def predict_metrics(req: MetricBatchRequest):
    if iso_detector is None:
        raise HTTPException(status_code=503, detail="Isolation Forest model not loaded")

    t0 = time.perf_counter()
    df = pd.DataFrame([r.model_dump() for r in req.records])

    raw_preds = iso_detector.predict(df)          # -1 or 1
    scores = iso_detector.anomaly_score(df)        # raw scores

    predictions = []
    for i, (pred, score) in enumerate(zip(raw_preds, scores)):
        is_anomaly = (pred == -1)
        predictions.append(MetricPrediction(
            index=i,
            is_anomaly=is_anomaly,
            anomaly_score=float(score),
            severity=score_to_severity(float(score)) if is_anomaly else "NONE",
            service_name=req.service_name,
            namespace=req.namespace,
        ))

    elapsed_ms = (time.perf_counter() - t0) * 1000
    return MetricBatchResponse(
        predictions=predictions,
        total_anomalies=sum(1 for p in predictions if p.is_anomaly),
        processing_time_ms=elapsed_ms,
    )


@app.post("/predict/logs", response_model=LogSequenceResponse)
async def predict_log_sequence(req: LogSequenceRequest):
    if lstm_detector is None:
        raise HTTPException(status_code=503, detail="LSTM model not loaded")

    t0 = time.perf_counter()
    X = np.array(req.sequence, dtype=np.float32)

    # Validate shape
    if X.ndim != 2:
        raise HTTPException(status_code=422,
                            detail="sequence must be a 2D array [seq_len, n_features]")
    if X.shape[0] != lstm_detector.sequence_len or X.shape[1] != lstm_detector.n_features:
        raise HTTPException(
            status_code=422,
            detail=f"Expected shape [{lstm_detector.sequence_len}, "
                   f"{lstm_detector.n_features}], got {list(X.shape)}",
        )

    X_batch = X[np.newaxis, ...]  # add batch dim
    errors = lstm_detector.reconstruction_error(X_batch)
    error = float(errors[0])
    is_anomaly = error > lstm_detector.threshold
    elapsed_ms = (time.perf_counter() - t0) * 1000

    return LogSequenceResponse(
        is_anomaly=is_anomaly,
        reconstruction_error=error,
        threshold=lstm_detector.threshold,
        severity=error_to_severity(error, lstm_detector.threshold) if is_anomaly else "NONE",
        service_name=req.service_name,
        namespace=req.namespace,
        processing_time_ms=elapsed_ms,
    )


@app.get("/model/info")
async def model_info():
    info: dict[str, Any] = {}
    if iso_detector is not None:
        info["isolation_forest"] = {
            "n_estimators": iso_detector.n_estimators,
            "contamination": iso_detector.contamination,
            "features": iso_detector.FEATURE_COLS,
        }
    if lstm_detector is not None:
        info["lstm_autoencoder"] = {
            "sequence_len": lstm_detector.sequence_len,
            "n_features": lstm_detector.n_features,
            "latent_dim": lstm_detector.latent_dim,
            "threshold": lstm_detector.threshold,
        }
    return info
