"""
train_model.py
---------------
Trains the two-layer ML pipeline described in Section 6.3 of the report:

  Layer 1  (binary):  Normal vs Malicious      -> RandomForestClassifier
  Layer 2  (multi):   attack-type classifier   -> SVM (one-vs-rest)

Both layers are Scikit-learn Pipelines that bundle preprocessing
(scaling + one-hot encoding) with the classifier, exactly as described
in Section 6.3.3, so the same transform is applied at train and
prediction time. Each pipeline is serialized with joblib.

Run:
    python ml/train_model.py
Produces:
    ml/layer1_pipeline.joblib
    ml/layer2_pipeline.joblib
    ml/metrics.json
"""
import json
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import accuracy_score, classification_report, f1_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.svm import SVC

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_PATH = os.path.join(BASE, "data", "traffic_dataset.csv")

NUMERIC_FEATURES = [
    "url_length", "num_special_chars", "num_params", "has_sql_keyword",
    "has_script_tag", "requests_per_10s", "failed_logins_per_min",
    "user_agent_entropy", "avg_packet_size", "flow_duration_ms",
]
CATEGORICAL_FEATURES = ["method"]
FEATURES = NUMERIC_FEATURES + CATEGORICAL_FEATURES


def build_preprocessor():
    return ColumnTransformer(
        transformers=[
            ("num", StandardScaler(), NUMERIC_FEATURES),
            ("cat", OneHotEncoder(handle_unknown="ignore"), CATEGORICAL_FEATURES),
        ]
    )


def main():
    if not os.path.exists(DATA_PATH):
        print("Dataset not found, generating it first...")
        os.system(f"{sys.executable} {os.path.join(BASE, 'data', 'generate_dataset.py')}")

    df = pd.read_csv(DATA_PATH)
    metrics = {}

    # ---------- Layer 1: Normal vs Malicious (Random Forest) ----------
    X = df[FEATURES]
    y1 = df["is_malicious"]
    X_train, X_test, y1_train, y1_test = train_test_split(
        X, y1, test_size=0.15, stratify=y1, random_state=42
    )

    layer1_pipeline = Pipeline(steps=[
        ("preprocess", build_preprocessor()),
        ("clf", RandomForestClassifier(
            n_estimators=200, max_depth=12, random_state=42, n_jobs=-1
        )),
    ])
    layer1_pipeline.fit(X_train, y1_train)
    y1_pred = layer1_pipeline.predict(X_test)
    metrics["layer1"] = {
        "accuracy": round(accuracy_score(y1_test, y1_pred), 4),
        "f1_macro": round(f1_score(y1_test, y1_pred, average="macro"), 4),
        "report": classification_report(y1_test, y1_pred, target_names=["Normal", "Malicious"], output_dict=True),
    }
    joblib.dump(layer1_pipeline, os.path.join(BASE, "ml", "layer1_pipeline.joblib"))

    # ---------- Layer 2: Attack-type classifier (SVM, one-vs-rest) ----------
    mal_df = df[df["is_malicious"] == 1]
    X2 = mal_df[FEATURES]
    y2 = mal_df["label"]
    X2_train, X2_test, y2_train, y2_test = train_test_split(
        X2, y2, test_size=0.15, stratify=y2, random_state=42
    )

    layer2_pipeline = Pipeline(steps=[
        ("preprocess", build_preprocessor()),
        ("clf", SVC(kernel="rbf", C=10, gamma="scale", decision_function_shape="ovr", probability=True, random_state=42)),
    ])
    layer2_pipeline.fit(X2_train, y2_train)
    y2_pred = layer2_pipeline.predict(X2_test)
    metrics["layer2"] = {
        "accuracy": round(accuracy_score(y2_test, y2_pred), 4),
        "f1_macro": round(f1_score(y2_test, y2_pred, average="macro"), 4),
        "report": classification_report(y2_test, y2_pred, output_dict=True),
    }
    joblib.dump(layer2_pipeline, os.path.join(BASE, "ml", "layer2_pipeline.joblib"))

    with open(os.path.join(BASE, "ml", "metrics.json"), "w") as f:
        json.dump(metrics, f, indent=2)

    print("Layer 1 (Normal vs Malicious) accuracy:", metrics["layer1"]["accuracy"])
    print("Layer 2 (Attack type) accuracy:", metrics["layer2"]["accuracy"])
    print("Saved: ml/layer1_pipeline.joblib, ml/layer2_pipeline.joblib, ml/metrics.json")


if __name__ == "__main__":
    main()
