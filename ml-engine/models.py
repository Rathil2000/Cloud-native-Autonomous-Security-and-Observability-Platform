"""
ML Detection Engine — Isolation Forest + LSTM Anomaly Detection
TCS iON AIP 225 — Cloud-native Security Platform
"""

import numpy as np
import pandas as pd
import pickle
import logging
from pathlib import Path
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, f1_score
import tensorflow as tf
from tensorflow.keras.models import Sequential, load_model
from tensorflow.keras.layers import LSTM, Dense, RepeatVector, TimeDistributed, Dropout
from tensorflow.keras.callbacks import EarlyStopping, ModelCheckpoint

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
logger = logging.getLogger(__name__)

MODELS_DIR = Path("models")
MODELS_DIR.mkdir(exist_ok=True)

# ─────────────────────────────────────────────
# Isolation Forest — Metric Anomaly Detection
# ─────────────────────────────────────────────

class MetricAnomalyDetector:
    """
    Unsupervised anomaly detection for cloud infrastructure metrics
    using the Isolation Forest algorithm.
    
    Features used:
      cpu_usage, memory_usage, network_in_bytes, network_out_bytes,
      disk_read_iops, disk_write_iops, http_request_rate, http_error_rate,
      pod_restart_count, latency_p95_ms
    """

    FEATURE_COLS = [
        "cpu_usage", "memory_usage", "network_in_bytes", "network_out_bytes",
        "disk_read_iops", "disk_write_iops", "http_request_rate",
        "http_error_rate", "pod_restart_count", "latency_p95_ms",
    ]

    def __init__(self, contamination: float = 0.05, n_estimators: int = 200):
        self.contamination = contamination
        self.n_estimators = n_estimators
        self.model: IsolationForest | None = None
        self.scaler = StandardScaler()

    def train(self, df: pd.DataFrame) -> None:
        logger.info("Training Isolation Forest on %d samples …", len(df))
        X = df[self.FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.fit_transform(X)
        self.model = IsolationForest(
            n_estimators=self.n_estimators,
            contamination=self.contamination,
            random_state=42,
            n_jobs=-1,
        )
        self.model.fit(X_scaled)
        logger.info("Isolation Forest training complete.")

    def predict(self, df: pd.DataFrame) -> np.ndarray:
        """Returns -1 (anomaly) or 1 (normal) for each row."""
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        X = df[self.FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.transform(X)
        return self.model.predict(X_scaled)

    def anomaly_score(self, df: pd.DataFrame) -> np.ndarray:
        """Returns raw anomaly scores (lower = more anomalous)."""
        X = df[self.FEATURE_COLS].fillna(0).values
        X_scaled = self.scaler.transform(X)
        return self.model.score_samples(X_scaled)

    def save(self, path: str = "models/isolation_forest.pkl") -> None:
        with open(path, "wb") as f:
            pickle.dump({"model": self.model, "scaler": self.scaler}, f)
        logger.info("Isolation Forest saved → %s", path)

    @classmethod
    def load(cls, path: str = "models/isolation_forest.pkl") -> "MetricAnomalyDetector":
        with open(path, "rb") as f:
            data = pickle.load(f)
        detector = cls()
        detector.model = data["model"]
        detector.scaler = data["scaler"]
        return detector


# ─────────────────────────────────────────────
# LSTM Autoencoder — Log Sequence Anomaly Detection
# ─────────────────────────────────────────────

class LogSequenceDetector:
    """
    LSTM Autoencoder for detecting anomalous log event sequences.
    
    The autoencoder learns to reconstruct normal log sequences.
    Sequences with reconstruction error above a learned threshold
    are flagged as anomalous (potential multi-step attacks).
    
    Input: fixed-length windows of tokenised log event codes.
    """

    def __init__(self, sequence_len: int = 50, n_features: int = 20,
                 latent_dim: int = 32, threshold_percentile: float = 95.0):
        self.sequence_len = sequence_len
        self.n_features = n_features
        self.latent_dim = latent_dim
        self.threshold_percentile = threshold_percentile
        self.model: tf.keras.Model | None = None
        self.threshold: float | None = None

    def _build_model(self) -> tf.keras.Model:
        model = Sequential([
            LSTM(64, input_shape=(self.sequence_len, self.n_features),
                 return_sequences=False),
            Dropout(0.2),
            RepeatVector(self.sequence_len),
            LSTM(64, return_sequences=True),
            Dropout(0.2),
            TimeDistributed(Dense(self.n_features)),
        ], name="lstm_autoencoder")
        model.compile(optimizer="adam", loss="mse")
        return model

    def train(self, X_train: np.ndarray, epochs: int = 30,
              batch_size: int = 64) -> tf.keras.callbacks.History:
        """
        X_train: shape (n_samples, sequence_len, n_features)
        Only normal sequences should be used for training.
        """
        logger.info("Building LSTM autoencoder …")
        self.model = self._build_model()
        self.model.summary()

        callbacks = [
            EarlyStopping(monitor="val_loss", patience=5, restore_best_weights=True),
            ModelCheckpoint("models/lstm_best.keras", save_best_only=True),
        ]
        history = self.model.fit(
            X_train, X_train,
            epochs=epochs,
            batch_size=batch_size,
            validation_split=0.15,
            callbacks=callbacks,
            verbose=1,
        )

        # Calibrate threshold on training reconstruction errors
        recon = self.model.predict(X_train, batch_size=batch_size)
        errors = np.mean(np.mean(np.square(X_train - recon), axis=2), axis=1)
        self.threshold = float(np.percentile(errors, self.threshold_percentile))
        logger.info("LSTM threshold set to %.6f (p%.0f)", self.threshold,
                    self.threshold_percentile)
        return history

    def predict(self, X: np.ndarray) -> np.ndarray:
        """Returns boolean array: True = anomaly."""
        if self.model is None:
            raise RuntimeError("Model not trained. Call train() first.")
        recon = self.model.predict(X, verbose=0)
        errors = np.mean(np.mean(np.square(X - recon), axis=2), axis=1)
        return errors > self.threshold

    def reconstruction_error(self, X: np.ndarray) -> np.ndarray:
        recon = self.model.predict(X, verbose=0)
        return np.mean(np.mean(np.square(X - recon), axis=2), axis=1)

    def save(self, model_path: str = "models/lstm_autoencoder.keras",
             meta_path: str = "models/lstm_meta.pkl") -> None:
        self.model.save(model_path)
        with open(meta_path, "wb") as f:
            pickle.dump({
                "sequence_len": self.sequence_len,
                "n_features": self.n_features,
                "latent_dim": self.latent_dim,
                "threshold": self.threshold,
                "threshold_percentile": self.threshold_percentile,
            }, f)
        logger.info("LSTM model saved → %s", model_path)

    @classmethod
    def load(cls, model_path: str = "models/lstm_autoencoder.keras",
             meta_path: str = "models/lstm_meta.pkl") -> "LogSequenceDetector":
        with open(meta_path, "rb") as f:
            meta = pickle.load(f)
        detector = cls(
            sequence_len=meta["sequence_len"],
            n_features=meta["n_features"],
            latent_dim=meta["latent_dim"],
            threshold_percentile=meta["threshold_percentile"],
        )
        detector.model = load_model(model_path)
        detector.threshold = meta["threshold"]
        return detector


# ─────────────────────────────────────────────
# Synthetic Data Generators (for demo/testing)
# ─────────────────────────────────────────────

def generate_metric_data(n_normal: int = 10000, n_anomaly: int = 500,
                         random_seed: int = 42) -> pd.DataFrame:
    """Generate synthetic cloud metrics with injected anomalies."""
    rng = np.random.default_rng(random_seed)

    # Normal data — correlated gaussian distributions
    normal = pd.DataFrame({
        "cpu_usage":          rng.normal(35, 10, n_normal).clip(0, 100),
        "memory_usage":       rng.normal(55, 12, n_normal).clip(0, 100),
        "network_in_bytes":   rng.normal(5e6, 1e6, n_normal).clip(0),
        "network_out_bytes":  rng.normal(3e6, 8e5, n_normal).clip(0),
        "disk_read_iops":     rng.normal(200, 50, n_normal).clip(0),
        "disk_write_iops":    rng.normal(150, 40, n_normal).clip(0),
        "http_request_rate":  rng.normal(500, 100, n_normal).clip(0),
        "http_error_rate":    rng.normal(0.02, 0.005, n_normal).clip(0, 1),
        "pod_restart_count":  rng.poisson(0.1, n_normal),
        "latency_p95_ms":     rng.normal(120, 30, n_normal).clip(1),
        "label": 0,  # 0=normal
    })

    # Anomaly data — extreme values simulating attacks/failures
    anomaly = pd.DataFrame({
        "cpu_usage":          rng.uniform(85, 100, n_anomaly),
        "memory_usage":       rng.uniform(80, 100, n_anomaly),
        "network_in_bytes":   rng.uniform(5e7, 1e8, n_anomaly),   # DDoS spike
        "network_out_bytes":  rng.uniform(4e7, 9e7, n_anomaly),   # exfiltration
        "disk_read_iops":     rng.uniform(800, 2000, n_anomaly),
        "disk_write_iops":    rng.uniform(700, 1800, n_anomaly),
        "http_request_rate":  rng.uniform(5000, 20000, n_anomaly), # traffic flood
        "http_error_rate":    rng.uniform(0.3, 1.0, n_anomaly),
        "pod_restart_count":  rng.integers(5, 30, n_anomaly),
        "latency_p95_ms":     rng.uniform(1000, 5000, n_anomaly),
        "label": 1,  # 1=anomaly
    })

    df = pd.concat([normal, anomaly], ignore_index=True).sample(frac=1, random_state=42)
    logger.info("Generated dataset: %d normal + %d anomaly samples", n_normal, n_anomaly)
    return df


def generate_log_sequences(n_normal: int = 5000, n_anomaly: int = 250,
                            seq_len: int = 50, n_features: int = 20,
                            random_seed: int = 42) -> tuple[np.ndarray, np.ndarray]:
    """
    Generate synthetic log event sequences.
    Returns (X, y) where X.shape = (n_samples, seq_len, n_features).
    """
    rng = np.random.default_rng(random_seed)

    # Normal: smooth, correlated sequences
    normal_base = rng.normal(0.3, 0.1, (n_normal, seq_len, n_features))
    normal_X = np.clip(normal_base, 0, 1)

    # Anomaly: sudden spikes or drops in specific feature channels
    anomaly_base = rng.normal(0.3, 0.1, (n_anomaly, seq_len, n_features))
    # Inject anomaly: random window with extreme values
    for i in range(n_anomaly):
        start = rng.integers(10, 40)
        channels = rng.choice(n_features, size=3, replace=False)
        anomaly_base[i, start:start+10, channels] = rng.uniform(0.8, 1.0, (10, 3))
    anomaly_X = np.clip(anomaly_base, 0, 1)

    X = np.concatenate([normal_X, anomaly_X], axis=0)
    y = np.array([0] * n_normal + [1] * n_anomaly)

    shuffle_idx = rng.permutation(len(X))
    return X[shuffle_idx], y[shuffle_idx]
