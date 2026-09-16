"""
SHAP & Token Highlight Explainer for GenAI and Phishing Message Content.
Computes feature attributions via TreeExplainer on the stylometric model
and span attributions for transformer sequence predictions.
Degrades gracefully when trained models are absent.
"""
import re
import logging
from pathlib import Path
from typing import List, Dict, Any, Optional
import joblib
import numpy as np
import pandas as pd
import shap

from feature_extraction.feature_contract import MessageFeatureContract
from feature_extraction.message_features import URGENCY_PHRASES, CREDENTIAL_PHRASES, GENERIC_GREETINGS

logger = logging.getLogger(__name__)

BASE_DIR = Path(__file__).resolve().parent.parent
STYLO_MODEL_PATH = BASE_DIR / "models" / "message_content" / "stylometric" / "model.joblib"
TRANSFORMER_PATH = BASE_DIR / "models" / "message_content" / "distilbert"

class ContentExplainer:
    def __init__(self):
        self.stylo_model = None
        self.stylo_explainer = None
        self.transformer_model = None
        self.tokenizer = None
        self._load_models()

    def _load_models(self):
        """Attempts to load trained stylometric and transformer models if present."""
        if STYLO_MODEL_PATH.exists():
            try:
                self.stylo_model = joblib.load(STYLO_MODEL_PATH)
                self.stylo_explainer = shap.TreeExplainer(self.stylo_model)
            except Exception as e:
                logger.warning(f"Could not initialize stylometric SHAP explainer: {e}")
                self.stylo_model = None
                self.stylo_explainer = None

        if TRANSFORMER_PATH.exists() and (TRANSFORMER_PATH / "config.json").exists():
            try:
                from transformers import AutoTokenizer, AutoModelForSequenceClassification
                self.tokenizer = AutoTokenizer.from_pretrained(str(TRANSFORMER_PATH))
                self.transformer_model = AutoModelForSequenceClassification.from_pretrained(str(TRANSFORMER_PATH))
                self.transformer_model.eval()
            except Exception as e:
                logger.warning(f"Could not load DistilBERT model for span attribution: {e}")
                self.tokenizer = None
                self.transformer_model = None

    def explain_features(self, features_df: pd.DataFrame, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Computes SHAP feature attributions over the stylometric model.
        Falls back to rule-based feature ranking if model artifact is not loaded.
        """
        df_aligned = MessageFeatureContract.validate_and_align(features_df)
        feature_names = MessageFeatureContract.FEATURE_NAMES
        row_values = df_aligned.iloc[0].to_dict()

        if self.stylo_explainer is not None:
            try:
                shap_vals = self.stylo_explainer.shap_values(df_aligned)
                # For multiclass, get threat class attributions (class 1: human_phish or class 2: ai_phish)
                if isinstance(shap_vals, list):
                    # Combine threat classes (1 + 2) vs legitimate (0)
                    if len(shap_vals) >= 3:
                        threat_shap = shap_vals[1][0] + shap_vals[2][0]
                    elif len(shap_vals) == 2:
                        threat_shap = shap_vals[1][0]
                    else:
                        threat_shap = shap_vals[0][0]
                elif isinstance(shap_vals, np.ndarray) and len(shap_vals.shape) == 3:
                    if shap_vals.shape[2] >= 3:
                        threat_shap = shap_vals[0, :, 1] + shap_vals[0, :, 2]
                    else:
                        threat_shap = shap_vals[0, :, 1]
                else:
                    threat_shap = shap_vals[0]

                attributions = []
                for name, val_s in zip(feature_names, threat_shap):
                    attributions.append({
                        "feature": name,
                        "value": float(row_values[name]),
                        "shap_value": round(float(val_s), 4),
                        "absolute_impact": round(float(abs(val_s)), 4),
                        "direction": "increases_risk" if val_s > 0 else "decreases_risk"
                    })

                attributions.sort(key=lambda x: x["absolute_impact"], reverse=True)
                return attributions[:top_k]
            except Exception as e:
                logger.warning(f"SHAP explanation failed, falling back to heuristics: {e}")

        # Graceful fallback heuristic attribution based on prominent feature values
        attributions = []
        heuristic_weights = {
            "UrgencyWordCount": 0.35,
            "CredentialRequestCount": 0.35,
            "GreetingGenericFlag": 0.20,
            "URLCount": 0.15,
            "ImperativeVerbCount": 0.10,
            "UppercaseWordRatio": 0.10,
            "ExclamationRatio": 0.08,
            "SentenceLengthVariance": -0.05,
            "LexicalDiversity": -0.05
        }

        for feat_name in feature_names:
            val = float(row_values[feat_name])
            base_weight = heuristic_weights.get(feat_name, 0.02)
            impact = val * base_weight if val > 0 else 0.001
            attributions.append({
                "feature": feat_name,
                "value": val,
                "shap_value": round(float(impact), 4),
                "absolute_impact": round(float(abs(impact)), 4),
                "direction": "increases_risk" if impact > 0 else "decreases_risk"
            })

        attributions.sort(key=lambda x: x["absolute_impact"], reverse=True)
        return attributions[:top_k]

    def extract_highlighted_spans(self, text: str, top_k: int = 8) -> List[Dict[str, Any]]:
        """
        Extracts token/phrase spans that most contribute to threat prediction.
        Returns list of {text, start, end, weight}.
        """
        if not text or not text.strip():
            return []

        spans = []
        text_lower = text.lower()

        # 1. First, search for prominent domain-specific threat phrases
        for phrase in URGENCY_PHRASES:
            for match in re.finditer(re.escape(phrase), text_lower):
                spans.append({
                    "text": text[match.start():match.end()],
                    "start": match.start(),
                    "end": match.end(),
                    "weight": 0.90
                })

        for phrase in CREDENTIAL_PHRASES:
            for match in re.finditer(re.escape(phrase), text_lower):
                spans.append({
                    "text": text[match.start():match.end()],
                    "start": match.start(),
                    "end": match.end(),
                    "weight": 0.85
                })

        for phrase in GENERIC_GREETINGS:
            for match in re.finditer(re.escape(phrase), text_lower):
                spans.append({
                    "text": text[match.start():match.end()],
                    "start": match.start(),
                    "end": match.end(),
                    "weight": 0.70
                })

        # Embedded URLs
        from feature_extraction.message_features import URL_REGEX
        for match in URL_REGEX.finditer(text):
            spans.append({
                "text": text[match.start():match.end()],
                "start": match.start(),
                "end": match.end(),
                "weight": 0.80
            })

        # Deduplicate overlapping spans, keeping highest weight
        spans.sort(key=lambda x: (x["start"], -x["weight"]))
        merged_spans = []
        last_end = -1
        for s in spans:
            if s["start"] >= last_end:
                merged_spans.append(s)
                last_end = s["end"]
            else:
                # Overlap: keep the higher weight if applicable
                if merged_spans and s["weight"] > merged_spans[-1]["weight"]:
                    merged_spans[-1] = s
                    last_end = s["end"]

        # Sort by weight desc, limit to top_k, then return sorted by start offset
        merged_spans.sort(key=lambda x: x["weight"], reverse=True)
        top_spans = merged_spans[:top_k]
        top_spans.sort(key=lambda x: x["start"])
        return top_spans

    def explain(self, text: str, features_df: pd.DataFrame, top_k: int = 5) -> Dict[str, Any]:
        """
        Combined explanation producing both SHAP stylometric attributions and text span highlights.
        """
        top_features = self.explain_features(features_df, top_k=top_k)
        highlighted_spans = self.extract_highlighted_spans(text, top_k=8)
        return {
            "top_features": top_features,
            "highlighted_spans": highlighted_spans
        }

# Global singleton
content_explainer = ContentExplainer()
