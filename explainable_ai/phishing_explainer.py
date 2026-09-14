"""
SHAP Explainer for Phishing URL Model.
Computes genuine feature attribution using shap.TreeExplainer on the trained champion model.
"""
from pathlib import Path
from typing import List, Dict, Any
import joblib
import numpy as np
import pandas as pd
import shap
from feature_extraction.feature_contract import URLFeatureContract

BASE_DIR = Path(__file__).resolve().parent.parent
MODEL_PATH = BASE_DIR / "models" / "phishing" / "model" / "phishing_model.joblib"

class PhishingShapExplainer:
    def __init__(self):
        self.model = joblib.load(MODEL_PATH)
        # TreeExplainer is exact and fast for RandomForest
        self.explainer = shap.TreeExplainer(self.model)
        
    def explain(self, features_df: pd.DataFrame, top_k: int = 5) -> List[Dict[str, Any]]:
        """
        Computes SHAP feature attributions for a single URL input DataFrame.
        Returns top_k features sorted by absolute SHAP contribution to Phishing (Class 1).
        """
        df_aligned = URLFeatureContract.validate_and_align(features_df)
        
        # Calculate shap values
        # For RandomForestClassifier, explainer.shap_values produces array of shape (samples, features, classes) or list [class0, class1]
        shap_vals = self.explainer.shap_values(df_aligned)
        
        # Normalize format: get attributions for Class 1 (Threat)
        if isinstance(shap_vals, list):
            # Binary classification list: [class0_vals, class1_vals]
            c1_vals = shap_vals[1][0]
        elif isinstance(shap_vals, np.ndarray) and len(shap_vals.shape) == 3:
            c1_vals = shap_vals[0, :, 1]
        else:
            c1_vals = shap_vals[0]
            
        feature_names = URLFeatureContract.FEATURE_NAMES
        row_values = df_aligned.iloc[0].to_dict()
        
        attributions = []
        for name, shap_val in zip(feature_names, c1_vals):
            attributions.append({
                "feature": name,
                "value": float(row_values[name]),
                "shap_value": round(float(shap_val), 4),
                "absolute_impact": round(float(abs(shap_val)), 4),
                "direction": "increases_risk" if shap_val > 0 else "decreases_risk"
            })
            
        # Sort by absolute SHAP importance
        attributions.sort(key=lambda x: x["absolute_impact"], reverse=True)
        return attributions[:top_k]

# Global singleton
phishing_explainer = PhishingShapExplainer()
