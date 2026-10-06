"""
Unsupervised Anomaly Detection Engine
Uses scikit-learn's Isolation Forest to compute normalized anomaly scores (0-100)
and explain which features contributed to deviations.
"""

from typing import List, Dict, Any, Tuple
import numpy as np
import pandas as pd
from sklearn.ensemble import IsolationForest
from backend.app.ml.preprocessor import MLPreprocessor


class AnomalyDetector:
    """Unsupervised threat and outlier detector using Isolation Forest."""

    def __init__(self, contamination: float = 0.08, random_state: int = 42):
        self.contamination = contamination
        self.random_state = random_state
        self.model = IsolationForest(
            contamination=contamination,
            random_state=random_state,
            n_estimators=100,
            n_jobs=-1
        )
        self.preprocessor = MLPreprocessor()
        self.is_fitted = False
        self.feature_names = []

    def fit_predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray, List[Dict[str, Any]]]:
        """
        Trains Isolation Forest on the dataset and returns:
        - is_anomaly (boolean array: True for anomalies)
        - anomaly_scores (float array scaled 0-100)
        - explanations (list of dictionaries explaining the top deviating features)
        """
        if len(df) < 5:
            # Not enough records to reliably fit isolation forest
            n = len(df)
            return np.zeros(n, dtype=bool), np.zeros(n), [{"reason": "Insufficient records for ML baseline"}] * n

        matrix, self.feature_names = self.preprocessor.fit_transform(df)

        self.model.fit(matrix)
        self.is_fitted = True

        # raw decision_function: lower values indicate higher anomaly (typically -0.5 to +0.5)
        raw_scores = self.model.decision_function(matrix)
        predictions = self.model.predict(matrix)  # -1 for anomaly, 1 for normal

        # Convert raw_scores to normalized 0-100 Anomaly Score
        # Minimum score ~ -0.5 (most anomalous) -> 100
        # Maximum score ~ +0.5 (most normal) -> 0
        min_s = float(raw_scores.min())
        max_s = float(raw_scores.max())
        score_range = max(max_s - min_s, 1e-6)

        # Inverted normalization: lower decision_function => higher risk
        norm_scores = 100.0 * (1.0 - (raw_scores - min_s) / score_range)
        is_anomaly = predictions == -1

        # Generate per-sample explanation of top deviating features
        explanations = []
        col_means = np.mean(matrix, axis=0)
        col_stds = np.std(matrix, axis=0) + 1e-6

        for i in range(len(df)):
            if is_anomaly[i]:
                # Find feature with maximum absolute z-score deviation from sample mean
                deviations = np.abs((matrix[i] - col_means) / col_stds)
                top_idx = int(np.argmax(deviations))
                top_feature = self.feature_names[top_idx] if top_idx < len(self.feature_names) else "metric_deviation"
                dev_val = round(float(deviations[top_idx]), 2)
                explanations.append({
                    "primary_anomalous_feature": top_feature,
                    "deviation_sigma": dev_val,
                    "summary": f"Abnormal statistical deviation ({dev_val}σ) in {top_feature} detected by Isolation Forest."
                })
            else:
                explanations.append({
                    "primary_anomalous_feature": "None",
                    "deviation_sigma": 0.0,
                    "summary": "Behavior consistent with baseline traffic distribution."
                })

        return is_anomaly, norm_scores, explanations
