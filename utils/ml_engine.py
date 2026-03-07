"""
Machine Learning Engine — Enhanced Threat Intelligence Analytics
================================================================
Modules:
1. ThreatClusterer    — K-Means + DBSCAN clustering for campaign detection
2. AnomalyDetector    — Isolation Forest for outlier / zero-day detection
3. IOCSimilarity      — TF-IDF cosine similarity for IOC correlation
4. DGADetector        — Entropy + n-gram analysis for DGA domain detection
5. TimeSeriesAnalyzer — Spike detection in IOC submission frequency
"""

import math
import numpy as np
import pandas as pd
from collections import Counter
from typing import List, Optional, Dict
from sklearn.cluster import KMeans, DBSCAN
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.metrics.pairwise import cosine_similarity


# ════════════════════════════════════════════════════════════════════
# 1. THREAT CLUSTERER — Campaign Detection
# ════════════════════════════════════════════════════════════════════
class ThreatClusterer:
    """
    Unsupervised ML engine for IOC campaign detection.
    Supports both K-Means (fixed K) and DBSCAN (density-based).

    Features engineered:
    - Shannon Entropy (detects DGA domains)
    - String Length (identifies URL obfuscation patterns)
    - Consensus Risk Score (aggregated threat intelligence)
    - Vowel-to-Consonant Ratio (DGA behavioral signal)
    - Digit Ratio (randomness indicator)
    - Subdomain Depth (deep nesting = suspicious)
    """

    def __init__(self, n_clusters: int = 4, n_init: int = 10, method: str = "kmeans"):
        self.n_clusters = n_clusters
        self.n_init = n_init
        self.method = method
        self.scaler = StandardScaler()
        self.model = None
        self.is_trained = False

    @staticmethod
    def calculate_shannon_entropy(string: str) -> float:
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

    @staticmethod
    def calculate_vowel_consonant_ratio(string: str) -> float:
        vowels = set("aeiouAEIOU")
        consonants = set("bcdfghjklmnpqrstvwxyzBCDFGHJKLMNPQRSTVWXYZ")
        v_count = sum(1 for c in string if c in vowels)
        c_count = sum(1 for c in string if c in consonants)
        return round(v_count / max(c_count, 1), 4)

    @staticmethod
    def calculate_digit_ratio(string: str) -> float:
        if not string:
            return 0.0
        digit_count = sum(1 for c in string if c.isdigit())
        return round(digit_count / len(string), 4)

    @staticmethod
    def count_subdomains(domain: str) -> int:
        return max(domain.count(".") - 1, 0)

    def extract_features(self, iocs: List[dict]) -> pd.DataFrame:
        features = []
        for record in iocs:
            ioc_str = record.get("ioc", "")
            risk_score = record.get("risk_score", 0)
            features.append({
                "ioc": ioc_str,
                "entropy": self.calculate_shannon_entropy(ioc_str),
                "string_length": len(ioc_str),
                "risk_score": float(risk_score),
                "vowel_consonant_ratio": self.calculate_vowel_consonant_ratio(ioc_str),
                "digit_ratio": self.calculate_digit_ratio(ioc_str),
                "subdomain_depth": self.count_subdomains(ioc_str),
            })
        return pd.DataFrame(features)

    def train_and_cluster(self, iocs: List[dict]) -> pd.DataFrame:
        if len(iocs) < 4:
            df = self.extract_features(iocs)
            df["cluster"] = 0
            df["cluster_label"] = "Insufficient Data"
            return df

        df = self.extract_features(iocs)
        feature_cols = ["entropy", "string_length", "risk_score",
                        "vowel_consonant_ratio", "digit_ratio", "subdomain_depth"]
        X = df[feature_cols].values
        X_scaled = self.scaler.fit_transform(X)

        if self.method == "dbscan":
            self.model = DBSCAN(eps=0.8, min_samples=2)
            df["cluster"] = self.model.fit_predict(X_scaled)
        else:
            self.model = KMeans(
                n_clusters=self.n_clusters, n_init=self.n_init,
                random_state=42, max_iter=300,
            )
            df["cluster"] = self.model.fit_predict(X_scaled)

        self.is_trained = True
        df["cluster_label"] = df["cluster"].map(self._generate_cluster_labels(df))
        return df

    def _generate_cluster_labels(self, df: pd.DataFrame) -> dict:
        labels = {}
        for cid in df["cluster"].unique():
            if cid == -1:
                labels[cid] = "⚪ Noise / Outlier (DBSCAN)"
                continue
            cd = df[df["cluster"] == cid]
            avg_ent = cd["entropy"].mean()
            avg_risk = cd["risk_score"].mean()
            avg_digit = cd["digit_ratio"].mean()
            if avg_ent > 3.5 and avg_risk > 60:
                labels[cid] = "🔴 High-Entropy C2/DGA"
            elif avg_risk > 60:
                labels[cid] = "🟠 High-Risk Infrastructure"
            elif avg_ent > 3.5 or avg_digit > 0.3:
                labels[cid] = "🟡 Suspicious Randomness"
            else:
                labels[cid] = "🟢 Low-Risk / Benign"
        return labels

    def predict_cluster(self, ioc: str, risk_score: float = 0) -> dict:
        if not self.is_trained or self.model is None:
            return {"error": "Model not trained."}
        entropy = self.calculate_shannon_entropy(ioc)
        features = np.array([[entropy, len(ioc), risk_score,
                              self.calculate_vowel_consonant_ratio(ioc),
                              self.calculate_digit_ratio(ioc),
                              self.count_subdomains(ioc)]])
        features_scaled = self.scaler.transform(features)
        if self.method == "kmeans":
            cluster = int(self.model.predict(features_scaled)[0])
        else:
            cluster = -1
        return {"ioc": ioc, "entropy": entropy, "risk_score": risk_score, "cluster": cluster}


# ════════════════════════════════════════════════════════════════════
# 2. ANOMALY DETECTOR — Isolation Forest
# ════════════════════════════════════════════════════════════════════
class AnomalyDetector:
    """
    Uses Isolation Forest to detect anomalous IOCs that don't fit
    normal patterns — potential zero-day or novel threats.
    """

    def __init__(self, contamination: float = 0.1):
        self.contamination = contamination
        self.model = IsolationForest(
            contamination=contamination, random_state=42, n_estimators=200,
        )
        self.scaler = StandardScaler()
        self.is_trained = False

    def train_and_detect(self, iocs: List[dict]) -> pd.DataFrame:
        clusterer = ThreatClusterer()
        df = clusterer.extract_features(iocs)
        feature_cols = ["entropy", "string_length", "risk_score",
                        "vowel_consonant_ratio", "digit_ratio", "subdomain_depth"]
        X = df[feature_cols].values

        if len(X) < 5:
            df["anomaly_score"] = 0
            df["is_anomaly"] = False
            return df

        X_scaled = self.scaler.fit_transform(X)
        self.model.fit(X_scaled)
        self.is_trained = True

        raw_scores = self.model.decision_function(X_scaled)
        predictions = self.model.predict(X_scaled)

        min_s, max_s = raw_scores.min(), raw_scores.max()
        if max_s - min_s > 0:
            normalized = 100 * (1 - (raw_scores - min_s) / (max_s - min_s))
        else:
            normalized = np.zeros_like(raw_scores)

        df["anomaly_score"] = np.round(normalized, 2)
        df["is_anomaly"] = predictions == -1
        return df


# ════════════════════════════════════════════════════════════════════
# 3. IOC SIMILARITY — TF-IDF Cosine Similarity
# ════════════════════════════════════════════════════════════════════
class IOCSimilarity:
    """
    Uses TF-IDF vectorization on IOC metadata (tags, descriptions)
    to find similar IOCs via cosine similarity.
    """

    def __init__(self):
        self.vectorizer = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2))
        self.tfidf_matrix = None
        self.ioc_labels = []

    def fit(self, iocs: List[dict]) -> None:
        documents = []
        self.ioc_labels = []
        for record in iocs:
            tags = record.get("tags", [])
            desc = record.get("description", "")
            ioc = record.get("ioc", "")
            documents.append(f"{ioc} {' '.join(tags)} {desc}")
            self.ioc_labels.append(ioc)
        if documents:
            self.tfidf_matrix = self.vectorizer.fit_transform(documents)

    def find_similar(self, query_ioc: str, top_k: int = 5) -> List[dict]:
        if self.tfidf_matrix is None:
            return [{"error": "Model not fitted."}]
        query_vec = self.vectorizer.transform([query_ioc])
        similarities = cosine_similarity(query_vec, self.tfidf_matrix).flatten()
        top_indices = similarities.argsort()[-top_k:][::-1]
        return [{"ioc": self.ioc_labels[i], "similarity_score": round(float(similarities[i]), 4)}
                for i in top_indices]

    def get_similarity_matrix(self) -> pd.DataFrame:
        if self.tfidf_matrix is None:
            return pd.DataFrame()
        sim_matrix = cosine_similarity(self.tfidf_matrix)
        return pd.DataFrame(sim_matrix, index=self.ioc_labels, columns=self.ioc_labels)


# ════════════════════════════════════════════════════════════════════
# 4. DGA DETECTOR — Domain Generation Algorithm Detection
# ════════════════════════════════════════════════════════════════════
class DGADetector:
    """
    Detects DGA domains using entropy, n-gram frequency,
    vowel/consonant ratio, digit ratio, and length analysis.
    Returns a DGA probability score (0-100).
    """

    COMMON_BIGRAMS = {
        "th", "he", "in", "er", "an", "re", "on", "at", "en", "nd",
        "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar",
        "st", "to", "nt", "ng", "se", "ha", "as", "ou", "io", "le",
        "ve", "co", "me", "de", "hi", "ri", "ro", "ic", "ne", "ea",
        "ra", "ce", "li", "ch", "ll", "be", "ma", "si", "om", "ur",
    }

    @staticmethod
    def extract_domain_body(domain: str) -> str:
        parts = domain.lower().replace("http://", "").replace("https://", "").split(".")
        return parts[-2] if len(parts) >= 2 else parts[0]

    def calculate_bigram_score(self, domain: str) -> float:
        body = self.extract_domain_body(domain)
        if len(body) < 2:
            return 0.0
        bigrams = [body[i:i+2] for i in range(len(body) - 1)]
        common_count = sum(1 for bg in bigrams if bg in self.COMMON_BIGRAMS)
        return round(common_count / len(bigrams), 4)

    def detect(self, domain: str) -> dict:
        body = self.extract_domain_body(domain)
        entropy = ThreatClusterer.calculate_shannon_entropy(body)
        vowel_ratio = ThreatClusterer.calculate_vowel_consonant_ratio(body)
        digit_ratio = ThreatClusterer.calculate_digit_ratio(body)
        bigram_score = self.calculate_bigram_score(domain)
        length = len(body)

        score = 0
        if entropy > 4.0: score += 25
        elif entropy > 3.5: score += 18
        elif entropy > 3.0: score += 10

        if bigram_score < 0.1: score += 25
        elif bigram_score < 0.3: score += 15
        elif bigram_score < 0.5: score += 8

        if vowel_ratio < 0.15 or vowel_ratio > 0.8: score += 15
        elif vowel_ratio < 0.25 or vowel_ratio > 0.6: score += 8

        if digit_ratio > 0.4: score += 20
        elif digit_ratio > 0.2: score += 12
        elif digit_ratio > 0.1: score += 5

        if length > 20: score += 15
        elif length > 15: score += 8
        elif length < 4: score += 10

        verdict = "LIKELY DGA" if score >= 60 else "SUSPICIOUS" if score >= 35 else "LIKELY LEGITIMATE"
        return {
            "domain": domain, "domain_body": body,
            "dga_score": min(score, 100), "verdict": verdict,
            "features": {
                "entropy": entropy, "bigram_score": bigram_score,
                "vowel_consonant_ratio": vowel_ratio,
                "digit_ratio": digit_ratio, "body_length": length,
            },
        }


# ════════════════════════════════════════════════════════════════════
# 5. TIME SERIES ANALYZER — IOC Submission Spike Detection
# ════════════════════════════════════════════════════════════════════
class TimeSeriesAnalyzer:
    """
    Detects spikes in IOC submission frequency using
    rolling-window Z-score analysis.
    """

    def __init__(self, window_size: int = 7, z_threshold: float = 2.0):
        self.window_size = window_size
        self.z_threshold = z_threshold

    def detect_spikes(self, timestamps: List[str]) -> pd.DataFrame:
        if not timestamps:
            return pd.DataFrame(columns=["date", "count", "z_score", "is_spike"])
        df = pd.DataFrame({"timestamp": pd.to_datetime(timestamps)})
        daily = df.groupby(df["timestamp"].dt.date).size().reset_index()
        daily.columns = ["date", "count"]
        daily["date"] = pd.to_datetime(daily["date"])
        daily = daily.sort_values("date").reset_index(drop=True)
        rolling_mean = daily["count"].rolling(window=self.window_size, min_periods=1).mean()
        rolling_std = daily["count"].rolling(window=self.window_size, min_periods=1).std().fillna(1)
        daily["z_score"] = ((daily["count"] - rolling_mean) / rolling_std).round(2)
        daily["is_spike"] = daily["z_score"] > self.z_threshold
        return daily
