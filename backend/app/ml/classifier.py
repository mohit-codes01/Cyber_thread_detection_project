"""
Supervised Threat Classification Module
Loads trained model (e.g. UNSW-NB15 Random Forest model) when matching schema is provided,
or falls back to unsupervised anomaly detection.
"""

import os
import joblib
from typing import Optional, Tuple
import numpy as np
import pandas as pd
from backend.app.config import settings


class ThreatClassifier:
    """Manages pre-trained supervised models for network threat classification."""

    def __init__(self, model_filename: str = "threat_model.pkl"):
        self.model_path = os.path.join(settings.MODELS_DIR, model_filename)
        self.model = None
        self._load_model()

    def _load_model(self):
        """Loads serialized model pipeline from disk if available."""
        if os.path.exists(self.model_path):
            try:
                self.model = joblib.load(self.model_path)
            except Exception as e:
                self.model = None

    def can_predict(self, df: pd.DataFrame) -> bool:
        """Determines if the uploaded dataframe has compatible features for the supervised model."""
        if self.model is None:
            return False
        # UNSW-NB15 characteristic columns check
        unsw_signals = {'sbytes', 'dbytes', 'sttl', 'dttl', 'proto', 'service', 'state', 'dur'}
        df_cols = set(c.lower() for c in df.columns)
        overlap = unsw_signals.intersection(df_cols)
        # If at least 3 characteristic columns exist, attempt supervised prediction
        return len(overlap) >= 3

    def predict(self, df: pd.DataFrame) -> Tuple[np.ndarray, np.ndarray]:
        """
        Executes supervised classification.
        Returns:
            predictions: binary array (0 = Normal, 1 = Malicious Threat)
            probabilities: confidence score array (0.0 to 1.0)
        """
        if not self.can_predict(df):
            n = len(df)
            return np.zeros(n, dtype=int), np.zeros(n, dtype=float)

        prediction_df = df.copy()
        # Drop columns not used in inference
        for col in ["id", "attack_cat", "label", "Prediction"]:
            if col in prediction_df.columns:
                prediction_df = prediction_df.drop(columns=[col])

        # Extract expected features from preprocessor pipeline if available
        try:
            preprocessor = self.model.named_steps.get("preprocessing")
            if preprocessor and hasattr(preprocessor, "transformers_"):
                expected_numeric = preprocessor.transformers_[0][2]
                expected_categorical = preprocessor.transformers_[1][2]

                # Ensure all expected columns exist in prediction dataframe
                for col in expected_numeric:
                    if col not in prediction_df.columns:
                        prediction_df[col] = np.nan
                for col in expected_categorical:
                    if col not in prediction_df.columns:
                        prediction_df[col] = "unknown"

            predictions = self.model.predict(prediction_df)
            if hasattr(self.model, "predict_proba"):
                prob_matrix = self.model.predict_proba(prediction_df)
                probabilities = prob_matrix[:, 1]
            else:
                probabilities = predictions.astype(float)

            return predictions, probabilities
        except Exception as e:
            n = len(df)
            return np.zeros(n, dtype=int), np.zeros(n, dtype=float)

