"""
Machine Learning Engine — Unsupervised Campaign Detection
Uses K-Means clustering with Shannon Entropy, string length,
and consensus risk score to identify threat campaigns.
"""

import math
import numpy as np
import pandas as pd
from collections import Counter
from sklearn.cluster import KMeans
from sklearn.preprocessing import StandardScaler
from typing import List, Optional


class ThreatClusterer:
    """
    Unsupervised ML engine for IOC campaign detection.

    Features:
    - Shannon Entropy (detects DGA domains)
    - String Length (identifies URL obfuscation patterns)
    - Consensus Risk Score (aggregated threat intelligence)

    Uses StandardScaler + K-Means for distance-based clustering.
    """

    def __init__(self, n_clusters: int = 4, n_init: int = 10):
        self.n_clusters = n_clusters
        self.n_init = n_init
        self.scaler = StandardScaler()
        self.model: Optional[KMeans] = None
        self.is_trained = False

    # ── Feature Engineering ─────────────────────────────────────────
    @staticmethod
    def calculate_shannon_entropy(string: str) -> float:
        """
        Calculate Shannon Entropy of a string.
        H(X) = -Σ p(x) * log2(p(x))

        High entropy → high randomness → potential DGA domain.
        Low entropy → structured/readable → likely legitimate.
        """
        if not string:
            return 0.0

        freq = Counter(string)
        length = len(string)
        entropy = 0.0

        for count in freq.values():
            probability = count / length
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return round(entropy, 4)

    def extract_features(self, iocs: List[dict]) -> pd.DataFrame:
        """
        Convert raw IOC records into numerical feature vectors.

        Expected input format:
        [
            {"ioc": "evil-domain.com", "risk_score": 85},
            {"ioc": "192.168.1.1", "risk_score": 30},
            ...
        ]
        """
        features = []

        for record in iocs:
            ioc_str = record.get("ioc", "")
            risk_score = record.get("risk_score", 0)

            features.append({
                "ioc": ioc_str,
                "entropy": self.calculate_shannon_entropy(ioc_str),
                "string_length": len(ioc_str),
                "risk_score": float(risk_score),
            })

        return pd.DataFrame(features)

    # ── Clustering ──────────────────────────────────────────────────
    def train_and_cluster(self, iocs: List[dict]) -> pd.DataFrame:
        """
        Run K-Means clustering on the IOC feature space.

        Returns DataFrame with cluster labels appended.
        """
        if len(iocs) < self.n_clusters:
            # Not enough data points — assign all to cluster 0
            df = self.extract_features(iocs)
            df["cluster"] = 0
            df["cluster_label"] = "Insufficient Data"
            return df

        df = self.extract_features(iocs)

        # Prepare numerical features
        feature_cols = ["entropy", "string_length", "risk_score"]
        X = df[feature_cols].values

        # Scale features (critical for K-Means distance calculations)
        X_scaled = self.scaler.fit_transform(X)

        # Train K-Means
        self.model = KMeans(
            n_clusters=self.n_clusters,
            n_init=self.n_init,
            random_state=42,
            max_iter=300,
        )
        df["cluster"] = self.model.fit_predict(X_scaled)
        self.is_trained = True

        # Label clusters based on centroid characteristics
        df["cluster_label"] = df["cluster"].map(self._generate_cluster_labels(df))

        return df

    def _generate_cluster_labels(self, df: pd.DataFrame) -> dict:
        """
        Generate human-readable labels for each cluster
        based on average feature values.
        """
        labels = {}
        for cluster_id in df["cluster"].unique():
            cluster_data = df[df["cluster"] == cluster_id]
            avg_entropy = cluster_data["entropy"].mean()
            avg_risk = cluster_data["risk_score"].mean()

            if avg_entropy > 3.5 and avg_risk > 60:
                labels[cluster_id] = "🔴 High-Entropy C2/DGA"
            elif avg_risk > 60:
                labels[cluster_id] = "🟠 High-Risk Infrastructure"
            elif avg_entropy > 3.5:
                labels[cluster_id] = "🟡 Suspicious Randomness"
            else:
                labels[cluster_id] = "🟢 Low-Risk / Benign"

        return labels

    # ── Prediction ──────────────────────────────────────────────────
    def predict_cluster(self, ioc: str, risk_score: float = 0) -> dict:
        """Predict which cluster a single new IOC belongs to."""
        if not self.is_trained or self.model is None:
            return {"error": "Model not trained. Run train_and_cluster() first."}

        entropy = self.calculate_shannon_entropy(ioc)
        features = np.array([[entropy, len(ioc), risk_score]])
        features_scaled = self.scaler.transform(features)
        cluster = int(self.model.predict(features_scaled)[0])

        return {
            "ioc": ioc,
            "entropy": entropy,
            "string_length": len(ioc),
            "risk_score": risk_score,
            "cluster": cluster,
        }
