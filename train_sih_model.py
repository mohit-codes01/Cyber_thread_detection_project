"""
Train SIH Problem Statement 145 Multi-Class Threat Detection Model.
Saves model bundle with feature medians for universal user data compatibility.
"""

import os
import joblib
import pandas as pd
import numpy as np
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.pipeline import Pipeline
from sklearn.impute import SimpleImputer
from sklearn.metrics import classification_report, accuracy_score

def train_and_save_sih_model():
    print("=" * 65)
    print("TRAINING SIH-145 MULTI-CLASS CYBER THREAT DETECTION MODEL")
    print("=" * 65)

    train_path = Path("data/sih/sih_ps145_train.csv")
    test_path = Path("data/sih/sih_ps145_test.csv")

    assert train_path.exists(), f"Train file not found: {train_path}"
    assert test_path.exists(), f"Test file not found: {test_path}"

    df_train = pd.read_csv(train_path)
    df_test = pd.read_csv(test_path)

    features = [c for c in df_train.columns if c not in ["flow_id", "label"]]
    X_train = df_train[features]
    y_train = df_train["label"]
    X_test = df_test[features]
    y_test = df_test["label"]

    print(f"Loaded {len(X_train)} training records and {len(X_test)} test records.")
    print(f"Features ({len(features)}): {features}")
    print(f"Target classes ({len(y_train.unique())}): {sorted(list(y_train.unique()))}")

    # Compute baseline medians for universal fallback/imputation
    feature_medians = {f: float(df_train[f].median()) for f in features}

    # Pipeline with imputer and Random Forest
    pipeline = Pipeline([
        ("imputer", SimpleImputer(strategy="median")),
        ("classifier", RandomForestClassifier(
            n_estimators=100,
            max_depth=20,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        ))
    ])

    print("\nFitting Random Forest Pipeline...")
    pipeline.fit(X_train, y_train)

    y_pred = pipeline.predict(X_test)
    acc = accuracy_score(y_test, y_pred)
    print(f"\nModel Test Accuracy: {acc * 100:.2f}%")
    print("\nClassification Report:\n", classification_report(y_test, y_pred, digits=4))

    # Package model bundle
    bundle = {
        "pipeline": pipeline,
        "features": features,
        "classes": sorted(list(y_train.unique())),
        "feature_medians": feature_medians,
        "model_name": "SIH-145 Multi-Threat Classifier",
        "description": "AI-Based Detection of Cyber Threats in Unidirectional IP Traffic (SIH PS-145)",
        "accuracy": float(acc),
        "total_training_records": len(df_train),
        "benign_label": "BENIGN"
    }

    out_dir = Path("models")
    out_dir.mkdir(exist_ok=True)
    out_file = out_dir / "sih_threat_model.pkl"

    joblib.dump(bundle, out_file, compress=3)
    size_mb = out_file.stat().st_size / (1024 * 1024)
    print(f"\nModel successfully saved to: {out_file} ({size_mb:.2f} MB)")
    print("=" * 65)

if __name__ == "__main__":
    train_and_save_sih_model()
