"""
Training pipeline for anomaly detection models.
Run: python train.py
"""

import logging
import numpy as np
import pandas as pd
from sklearn.metrics import classification_report, f1_score
from models import (
    MetricAnomalyDetector, LogSequenceDetector,
    generate_metric_data, generate_log_sequences,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)


def train_isolation_forest():
    logger.info("=" * 60)
    logger.info("ISOLATION FOREST — Metric Anomaly Detection")
    logger.info("=" * 60)

    df = generate_metric_data(n_normal=10000, n_anomaly=500)
    train_df = df[df["label"] == 0].drop(columns=["label"])  # train on normal only

    detector = MetricAnomalyDetector(contamination=0.05, n_estimators=200)
    detector.train(train_df)

    # Evaluate on full dataset
    preds_raw = detector.predict(df.drop(columns=["label"]))
    preds = (preds_raw == -1).astype(int)  # -1=anomaly → 1
    labels = df["label"].values

    f1 = f1_score(labels, preds)
    logger.info("F1-score: %.4f", f1)
    print(classification_report(labels, preds, target_names=["normal", "anomaly"]))

    detector.save("models/isolation_forest.pkl")
    return f1


def train_lstm():
    logger.info("=" * 60)
    logger.info("LSTM AUTOENCODER — Log Sequence Anomaly Detection")
    logger.info("=" * 60)

    SEQ_LEN, N_FEATURES = 50, 20
    X, y = generate_log_sequences(
        n_normal=5000, n_anomaly=250,
        seq_len=SEQ_LEN, n_features=N_FEATURES,
    )

    # Train ONLY on normal sequences
    X_train = X[y == 0]
    logger.info("Training on %d normal sequences …", len(X_train))

    detector = LogSequenceDetector(
        sequence_len=SEQ_LEN, n_features=N_FEATURES,
        latent_dim=32, threshold_percentile=95.0,
    )
    history = detector.train(X_train, epochs=30, batch_size=64)

    # Evaluate on full dataset
    preds = detector.predict(X).astype(int)
    f1 = f1_score(y, preds)
    logger.info("LSTM F1-score: %.4f", f1)
    print(classification_report(y, preds, target_names=["normal", "anomaly"]))

    detector.save(
        model_path="models/lstm_autoencoder.keras",
        meta_path="models/lstm_meta.pkl",
    )
    final_loss = history.history["val_loss"][-1]
    logger.info("Final validation loss: %.6f", final_loss)
    return f1


if __name__ == "__main__":
    iso_f1 = train_isolation_forest()
    lstm_f1 = train_lstm()

    print("\n" + "=" * 60)
    print("TRAINING SUMMARY")
    print("=" * 60)
    print(f"  Isolation Forest F1:  {iso_f1:.4f}")
    print(f"  LSTM Autoencoder F1:  {lstm_f1:.4f}")
    target_met = "✓" if iso_f1 >= 0.92 and lstm_f1 >= 0.92 else "✗"
    print(f"  Target (>= 0.92):     {target_met}")
    print("=" * 60)
