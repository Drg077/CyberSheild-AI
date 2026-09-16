"""
Learned Risk Fusion Meta-Classifier Training Script.
Builds a synthetic multi-evidence evaluation set from held-out phishing, malware, and message splits,
trains an interpretable LogisticRegression meta-model, compares directly with the fixed-weight baseline,
and serializes model artifacts and empirical evaluation metadata.
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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score,
    roc_auc_score,
    brier_score_loss,
    f1_score,
    log_loss
)

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import settings
from risk_engine.fusion_model import FusionModel
from risk_engine.risk_score import compute_url_context, compute_pe_context, compute_message_context

OUTPUT_DIR = BASE_DIR / "models" / "fusion"
METADATA_DIR = OUTPUT_DIR / "metadata"

def generate_fusion_dataset():
    """
    Generates training rows by running existing models or test-split distributions
    with partial and multi-modal evidence.
    """
    rows = []
    
    # 1. URL Phishing held-out set
    phish_test_path = settings.DATA_DIR / "processed" / "phishing" / "X_test.csv"
    phish_y_path = settings.DATA_DIR / "processed" / "phishing" / "y_test.csv"
    phish_model_path = settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib"
    
    if phish_test_path.exists() and phish_model_path.exists():
        X_phish = pd.read_csv(phish_test_path)
        y_phish = pd.read_csv(phish_y_path).squeeze("columns")
        m_phish = joblib.load(phish_model_path)
        probs_phish = m_phish.predict_proba(X_phish)[:, 1]
        
        for idx in range(min(1500, len(X_phish))):
            f_dict = X_phish.iloc[idx].to_dict()
            ctx = compute_url_context(f_dict)
            rows.append({
                "p_phishing": float(probs_phish[idx]),
                "p_malware": 0.0,
                "p_genai_phishing": 0.0,
                "context_score": float(ctx),
                "has_url": 1.0,
                "has_file": 0.0,
                "has_message": 0.0,
                "ground_truth": int(y_phish.iloc[idx])
            })
            
    # 2. Malware held-out set
    mal_test_path = settings.DATA_DIR / "processed" / "malware" / "X_test.csv"
    mal_y_path = settings.DATA_DIR / "processed" / "malware" / "y_test.csv"
    mal_model_path = settings.MODELS_DIR / "malware" / "model" / "malware_model.joblib"
    
    if mal_test_path.exists() and mal_model_path.exists():
        X_mal = pd.read_csv(mal_test_path)
        y_mal = pd.read_csv(mal_y_path).squeeze("columns")
        m_mal = joblib.load(mal_model_path)
        probs_mal = m_mal.predict_proba(X_mal)[:, 1]
        
        for idx in range(min(1500, len(X_mal))):
            f_dict = X_mal.iloc[idx].to_dict()
            ctx = compute_pe_context(f_dict)
            rows.append({
                "p_phishing": 0.0,
                "p_malware": float(probs_mal[idx]),
                "p_genai_phishing": 0.0,
                "context_score": float(ctx),
                "has_url": 0.0,
                "has_file": 1.0,
                "has_message": 0.0,
                "ground_truth": int(y_mal.iloc[idx])
            })

    # 3. Message held-out set (if processed)
    msg_test_path = settings.DATA_DIR / "processed" / "messages" / "X_test.csv"
    msg_y_path = settings.DATA_DIR / "processed" / "messages" / "y_test.csv"
    msg_model_path = settings.MODELS_DIR / "message_content" / "stylometric" / "model.joblib"
    
    if msg_test_path.exists() and msg_model_path.exists():
        X_msg = pd.read_csv(msg_test_path)
        y_msg = pd.read_csv(msg_y_path).squeeze("columns")
        m_msg = joblib.load(msg_model_path)
        probs_msg = m_msg.predict_proba(X_msg)
        # Combine threat classes (1: human + 2: ai)
        threat_probs = probs_msg[:, 1] + (probs_msg[:, 2] if probs_msg.shape[1] > 2 else 0.0)
        
        for idx in range(min(1500, len(X_msg))):
            f_dict = X_msg.iloc[idx].to_dict()
            ctx = compute_message_context(f_dict)
            gt = 1 if y_msg.iloc[idx] in [1, 2] else 0
            rows.append({
                "p_phishing": 0.0,
                "p_malware": 0.0,
                "p_genai_phishing": float(threat_probs[idx]),
                "context_score": float(ctx),
                "has_url": 0.0,
                "has_file": 0.0,
                "has_message": 1.0,
                "ground_truth": gt
            })
            
    df = pd.DataFrame(rows)
    return df

def train_fusion_model():
    print("=" * 60)
    print("LEARNED RISK FUSION META-CLASSIFIER TRAINING")
    print("=" * 60)
    
    df = generate_fusion_dataset()
    if df.empty or len(df) < 50:
        raise RuntimeError("Insufficient held-out evaluation samples to train fusion meta-classifier.")
        
    print(f"Generated multi-evidence training set: {len(df)} samples")
    
    feature_cols = FusionModel.FEATURE_NAMES
    X = df[feature_cols]
    y = df["ground_truth"]
    
    # Stratified split 80/20 train/test
    from sklearn.model_selection import train_test_split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )
    
    # Train LogisticRegression meta-classifier
    clf = LogisticRegression(C=1.0, penalty="l2", solver="lbfgs", max_iter=500, random_state=42)
    t0 = time.time()
    clf.fit(X_train, y_train)
    train_duration = time.time() - t0
    
    # Evaluate Learned Model
    y_prob_learned = clf.predict_proba(X_test)[:, 1]
    y_pred_learned = (y_prob_learned >= 0.50).astype(int)
    
    acc_learned = accuracy_score(y_test, y_pred_learned)
    auc_learned = roc_auc_score(y_test, y_prob_learned)
    brier_learned = brier_score_loss(y_test, y_prob_learned)
    f1_learned = f1_score(y_test, y_pred_learned, zero_division=0)
    
    # Evaluate Fixed-Weight Baseline on the exact same rows
    fallback_model = FusionModel(model_path=Path("non_existent_path"))
    y_prob_baseline = []
    for _, row in X_test.iterrows():
        score = fallback_model.predict_risk(
            p_phishing=row["p_phishing"] if row["has_url"] == 1.0 else None,
            p_malware=row["p_malware"] if row["has_file"] == 1.0 else None,
            p_genai_phishing=row["p_genai_phishing"] if row["has_message"] == 1.0 else None,
            context_score=row["context_score"],
            has_url=bool(row["has_url"]),
            has_file=bool(row["has_file"]),
            has_message=bool(row["has_message"])
        )
        y_prob_baseline.append(score / 100.0)
        
    y_prob_baseline = np.array(y_prob_baseline)
    y_pred_baseline = (y_prob_baseline >= 0.50).astype(int)
    
    acc_base = accuracy_score(y_test, y_pred_baseline)
    auc_base = roc_auc_score(y_test, y_prob_baseline)
    brier_base = brier_score_loss(y_test, y_prob_baseline)
    f1_base = f1_score(y_test, y_pred_baseline, zero_division=0)
    
    print("\nEmpirical Comparison on Held-Out Test Split:")
    print(f"  Learned Fusion Meta-Classifier:")
    print(f"    Accuracy:     {acc_learned:.4f}")
    print(f"    F1-Score:     {f1_learned:.4f}")
    print(f"    ROC-AUC:      {auc_learned:.4f}")
    print(f"    Brier Score:  {brier_learned:.4f}")
    print(f"  Fixed-Weight Baseline:")
    print(f"    Accuracy:     {acc_base:.4f}")
    print(f"    F1-Score:     {f1_base:.4f}")
    print(f"    ROC-AUC:      {auc_base:.4f}")
    print(f"    Brier Score:  {brier_base:.4f}")
    
    # Save artifacts
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    METADATA_DIR.mkdir(parents=True, exist_ok=True)
    
    save_path = OUTPUT_DIR / "model.joblib"
    joblib.dump(clf, save_path)
    print(f"\nSaved learned fusion model to: {save_path}")
    
    # Learned weights inspection
    coefs = dict(zip(feature_cols, [round(float(c), 4) for c in clf.coef_[0]]))
    intercept = round(float(clf.intercept_[0]), 4)
    
    metadata = {
        "model_type": "LogisticRegression_Risk_Fusion",
        "model_version": "v1.0.0",
        "training_date": datetime.now(timezone.utc).isoformat(),
        "training_duration_seconds": round(train_duration, 3),
        "features": feature_cols,
        "learned_coefficients": coefs,
        "learned_intercept": intercept,
        "evaluation_comparison": {
            "test_samples": len(X_test),
            "learned_fusion": {
                "accuracy": round(float(acc_learned), 4),
                "f1_score": round(float(f1_learned), 4),
                "roc_auc": round(float(auc_learned), 4),
                "brier_score": round(float(brier_learned), 4)
            },
            "fixed_weight_baseline": {
                "accuracy": round(float(acc_base), 4),
                "f1_score": round(float(f1_base), 4),
                "roc_auc": round(float(auc_base), 4),
                "brier_score": round(float(brier_base), 4)
            }
        }
    }
    
    meta_path = METADATA_DIR / "metadata.json"
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)
    print(f"Saved metadata to: {meta_path}")
    print("=" * 60)

if __name__ == "__main__":
    train_fusion_model()
