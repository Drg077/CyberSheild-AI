"""
Adversarial Robustness Evaluation & Reporting Script.
Executes URL and message evasion attack harnesses, measures metrics degradation (clean vs perturbed),
and exports the empirical robustness report to docs/adversarial_robustness_report.json.
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

BASE_DIR = Path(__file__).resolve().parent.parent
if str(BASE_DIR) not in sys.path:
    sys.path.insert(0, str(BASE_DIR))

from backend.config import settings
from feature_extraction.url_features import extract_url_features_df
from feature_extraction.message_features import extract_message_features_df
from tests.test_adversarial.test_url_perturbation import (
    REPRESENTATIVE_PHISHING_URLS,
    apply_homograph_substitution,
    apply_benign_subdomain_injection,
    apply_path_padding
)
from tests.test_adversarial.test_message_perturbation import (
    REPRESENTATIVE_AI_PHISHING,
    apply_synonym_substitution
)

DOCS_DIR = BASE_DIR / "docs"
REPORT_PATH = DOCS_DIR / "adversarial_robustness_report.json"

def generate_adversarial_report():
    print("=" * 60)
    print("ADVERSARIAL ROBUSTNESS EVALUATION REPORT GENERATOR")
    print("=" * 60)

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    report = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "url_detector_robustness": {},
        "message_detector_robustness": {}
    }

    # 1. Evaluate URL Detector Robustness
    phish_model_path = settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib"
    if phish_model_path.exists():
        url_model = joblib.load(phish_model_path)
        clean_df = extract_url_features_df(REPRESENTATIVE_PHISHING_URLS)
        clean_probs = url_model.predict_proba(clean_df.values)[:, 1]
        clean_recall = float(np.mean(clean_probs >= 0.50))
        clean_mean_confidence = float(np.mean(clean_probs))

        # Test attacks
        homograph_urls = [apply_homograph_substitution(u) for u in REPRESENTATIVE_PHISHING_URLS]
        subdomain_urls = [apply_benign_subdomain_injection(u) for u in REPRESENTATIVE_PHISHING_URLS]
        padded_urls = [apply_path_padding(u) for u in REPRESENTATIVE_PHISHING_URLS]

        h_probs = url_model.predict_proba(extract_url_features_df(homograph_urls).values)[:, 1]
        s_probs = url_model.predict_proba(extract_url_features_df(subdomain_urls).values)[:, 1]
        p_probs = url_model.predict_proba(extract_url_features_df(padded_urls).values)[:, 1]

        report["url_detector_robustness"] = {
            "clean_baseline": {
                "sample_count": len(REPRESENTATIVE_PHISHING_URLS),
                "recall": round(clean_recall, 4),
                "mean_threat_confidence": round(clean_mean_confidence, 4)
            },
            "homograph_attack": {
                "recall": round(float(np.mean(h_probs >= 0.50)), 4),
                "mean_threat_confidence": round(float(np.mean(h_probs)), 4),
                "recall_delta": round(clean_recall - float(np.mean(h_probs >= 0.50)), 4)
            },
            "subdomain_injection_attack": {
                "recall": round(float(np.mean(s_probs >= 0.50)), 4),
                "mean_threat_confidence": round(float(np.mean(s_probs)), 4),
                "recall_delta": round(clean_recall - float(np.mean(s_probs >= 0.50)), 4)
            },
            "path_padding_attack": {
                "recall": round(float(np.mean(p_probs >= 0.50)), 4),
                "mean_threat_confidence": round(float(np.mean(p_probs)), 4),
                "recall_delta": round(clean_recall - float(np.mean(p_probs >= 0.50)), 4)
            }
        }
        print("URL Robustness Evaluation complete.")

    # 2. Evaluate Message Detector Robustness
    msg_model_path = settings.MODELS_DIR / "message_content" / "stylometric" / "model.joblib"
    if msg_model_path.exists():
        msg_model = joblib.load(msg_model_path)
        clean_df = extract_message_features_df(REPRESENTATIVE_AI_PHISHING)
        clean_probs = msg_model.predict_proba(clean_df.values)
        clean_threat_probs = [p[1] + (p[2] if len(p) > 2 else 0) for p in clean_probs]
        clean_rec = float(np.mean(np.array(clean_threat_probs) >= 0.50))

        pert_messages = [apply_synonym_substitution(m) for m in REPRESENTATIVE_AI_PHISHING]
        pert_df = extract_message_features_df(pert_messages)
        pert_probs = msg_model.predict_proba(pert_df.values)
        pert_threat_probs = [p[1] + (p[2] if len(p) > 2 else 0) for p in pert_probs]
        pert_rec = float(np.mean(np.array(pert_threat_probs) >= 0.50))

        report["message_detector_robustness"] = {
            "clean_baseline": {
                "sample_count": len(REPRESENTATIVE_AI_PHISHING),
                "recall": round(clean_rec, 4),
                "mean_threat_confidence": round(float(np.mean(clean_threat_probs)), 4)
            },
            "synonym_paraphrase_attack": {
                "recall": round(pert_rec, 4),
                "mean_threat_confidence": round(float(np.mean(pert_threat_probs)), 4),
                "recall_delta": round(clean_rec - pert_rec, 4)
            }
        }
    else:
        report["message_detector_robustness"] = {
            "status": "Model artifact not trained yet. Run train_message_stylometric.py first."
        }

    with open(REPORT_PATH, "w") as f:
        json.dump(report, f, indent=2)

    print(f"Adversarial robustness report successfully saved to: {REPORT_PATH}")
    print("=" * 60)

if __name__ == "__main__":
    generate_adversarial_report()
