"""
Message Content Stylometric Model Training & Evaluation Script.
Trains GradientBoosting / Tree-based classifier on 24 stylometric features for 3-class message threat classification:
  Class 0: Legitimate
  Class 1: Human Phishing
  Class 2: AI Phishing (GenAI)
Saves champion model, SHAP background, and empirical test metrics to metadata.json.
"""
import sys
import os
import json
import time
from datetime import datetime, timezone
from pathlib import Path
import numpy as np
import pandas as pd
import joblib
from sklearn.ensemble import GradientBoostingClassifier, RandomForestClassifier, HistGradientBoostingClassifier
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    classification_report,
    confusion_matrix
)
import shap

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from feature_extraction.feature_contract import MessageFeatureContract

DATA_DIR = BASE_DIR / "data" / "processed" / "messages"
MODEL_OUTPUT_DIR = BASE_DIR / "models" / "message_content" / "stylometric"
METADATA_DIR = MODEL_OUTPUT_DIR / "metadata"

CLASS_NAMES = ["legitimate", "human_phishing", "ai_phishing"]

def evaluate_stylometric_model(name: str, model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    """Calculates accuracy, per-class precision/recall/F1, macro-F1, confusion matrix, and latency."""
    t0 = time.perf_counter()
    y_pred = model.predict(X_test)
    y_proba = model.predict_proba(X_test)
    t1 = time.perf_counter()
    
    latency_ms_per_sample = ((t1 - t0) * 1000) / len(X_test) if len(X_test) > 0 else 0.0
    
    acc = accuracy_score(y_test, y_pred)
    macro_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
    weighted_f1 = f1_score(y_test, y_pred, average="weighted", zero_division=0)
    
    precisions = precision_score(y_test, y_pred, average=None, zero_division=0)
    recalls = recall_score(y_test, y_pred, average=None, zero_division=0)
    f1s = f1_score(y_test, y_pred, average=None, zero_division=0)
    
    per_class = {}
    for idx, cname in enumerate(CLASS_NAMES):
        per_class[cname] = {
            "precision": round(float(precisions[idx]), 4) if idx < len(precisions) else 0.0,
            "recall": round(float(recalls[idx]), 4) if idx < len(recalls) else 0.0,
            "f1_score": round(float(f1s[idx]), 4) if idx < len(f1s) else 0.0
        }
        
    cm = confusion_matrix(y_test, y_pred).tolist()
    
    return {
        "model_name": name,
        "accuracy": round(float(acc), 4),
        "macro_f1": round(float(macro_f1), 4),
        "weighted_f1": round(float(weighted_f1), 4),
        "per_class_metrics": per_class,
        "confusion_matrix": cm,
        "latency_ms_per_sample": round(float(latency_ms_per_sample), 4)
    }

def train_message_stylometric_model():
    print("=" * 60)
    print("MESSAGE CONTENT STYLOMETRIC MODEL TRAINING")
    print("=" * 60)
    
    if not (DATA_DIR / "X_train.csv").exists() or not (DATA_DIR / "y_train.csv").exists():
        raise FileNotFoundError(
            f"Processed message training data not found in {DATA_DIR}.\n"
            f"Please run `python scripts/prepare_message_data.py` first with authentic datasets in data/raw/messages/."
        )
        
    X_train = pd.read_csv(DATA_DIR / "X_train.csv")
    y_train = pd.read_csv(DATA_DIR / "y_train.csv").squeeze("columns")
    X_val = pd.read_csv(DATA_DIR / "X_val.csv")
    y_val = pd.read_csv(DATA_DIR / "y_val.csv").squeeze("columns")
    X_test = pd.read_csv(DATA_DIR / "X_test.csv")
    y_test = pd.read_csv(DATA_DIR / "y_test.csv").squeeze("columns")
    
    # Validate feature contracts
    X_train = MessageFeatureContract.validate_and_align(X_train)
    X_val = MessageFeatureContract.validate_and_align(X_val)
    X_test = MessageFeatureContract.validate_and_align(X_test)
    
    print(f"Loaded training data: {len(X_train)} samples, {X_train.shape[1]} features")
    print(f"Loaded validation data: {len(X_val)} samples")
    print(f"Loaded test data: {len(X_test)} samples")
    
    # Candidate stylometric classifiers
    candidates = {
        "GradientBoostingClassifier": GradientBoostingClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=5,
            random_state=42
        ),
        "RandomForestClassifier": RandomForestClassifier(
            n_estimators=150,
            max_depth=12,
            min_samples_split=4,
            random_state=42,
            n_jobs=-1
        )
    }
    
    # Try XGBoost if available
    try:
        from xgboost import XGBClassifier
        candidates["XGBClassifier"] = XGBClassifier(
            n_estimators=150,
            learning_rate=0.1,
            max_depth=5,
            random_state=42,
            eval_metric="mlogloss"
        )
    except ImportError:
        pass
        
    best_name = None
    best_model = None
    best_macro_f1 = -1.0
    all_evaluations = []
    
    for name, model in candidates.items():
        print(f"\nTraining candidate model: {name}...")
        t0 = time.time()
        model.fit(X_train, y_train)
        duration = time.time() - t0
        print(f"  Completed training in {duration:.2f}s")
        
        eval_metrics = evaluate_stylometric_model(name, model, X_test, y_test)
        eval_metrics["training_time_seconds"] = round(duration, 2)
        all_evaluations.append(eval_metrics)
        
        print(f"  Test Accuracy: {eval_metrics['accuracy']:.4f}, Macro-F1: {eval_metrics['macro_f1']:.4f}")
        
        if eval_metrics["macro_f1"] > best_macro_f1:
            best_macro_f1 = eval_metrics["macro_f1"]
            best_name = name
            best_model = model
            
    print("\n" + "=" * 60)
    print(f"CHAMPION STYLOMETRIC MODEL: {best_name} (Macro-F1: {best_macro_f1:.4f})")
    print("=" * 60)
    
    # Save artifacts
    MODEL_OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    
    model_save_path = MODEL_OUTPUT_DIR / "model.joblib"
    joblib.dump(best_model, model_save_path)
    print(f"Saved champion model to: {model_save_path}")
    
    # Save SHAP background (100 samples)
    bg_sample = X_train.sample(n=min(100, len(X_train)), random_state=42)
    shap_bg_path = METADATA_DIR / "shap_background.joblib"
    joblib.dump(bg_sample, shap_bg_path)
    print(f"Saved SHAP background to: {shap_bg_path}")
    
    champion_meta = next(m for m in all_evaluations if m["model_name"] == best_name)
    
    metadata = {
        "model_type": best_name,
        "model_version": "v1.0.0",
        "task": "stylometric_message_threat_prediction",
        "classes": CLASS_NAMES,
        "training_date": datetime.now(timezone.utc).isoformat(),
        "feature_schema_version": MessageFeatureContract.SCHEMA_VERSION,
        "features": MessageFeatureContract.FEATURE_NAMES,
        "candidate_evaluations": all_evaluations,
        "champion_metrics": champion_meta
    }
    
    meta_path = METADATA_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved metadata to: {meta_path}")

if __name__ == "__main__":
    train_message_stylometric_model()
