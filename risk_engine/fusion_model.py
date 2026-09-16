"""
Learned Risk Fusion Meta-Classifier.
Fuses multi-modal model probabilities and contextual risk scores into a unified 0-100 risk score
using an interpretable LogisticRegression meta-model with support for partial evidence flags.
Gracefully falls back to baseline weighted linear combination if the model artifact is not found.
"""
import logging
from pathlib import Path
from typing import Optional, Dict, Any
import numpy as np
import joblib

from backend.config import settings

logger = logging.getLogger(__name__)

FUSION_MODEL_PATH = settings.MODELS_DIR / "fusion" / "model.joblib"

class FusionModel:
    FEATURE_NAMES = [
        "p_phishing",
        "p_malware",
        "p_genai_phishing",
        "context_score",
        "has_url",
        "has_file",
        "has_message"
    ]

    def __init__(self, model_path: Optional[Path] = None):
        self.model_path = model_path or FUSION_MODEL_PATH
        self.model = None
        self._load_model()

    def _load_model(self):
        if self.model_path.exists():
            try:
                self.model = joblib.load(self.model_path)
                logger.info(f"Loaded learned fusion meta-classifier from {self.model_path}")
            except Exception as e:
                logger.warning(f"Failed to load fusion model from {self.model_path}: {e}. Falling back to fixed weights.")
                self.model = None
        else:
            logger.warning(f"Learned fusion model not found at {self.model_path}. Operating in fixed-weight fallback mode.")
            self.model = None

    @property
    def is_loaded(self) -> bool:
        return self.model is not None

    def predict_risk(
        self,
        p_phishing: Optional[float] = None,
        p_malware: Optional[float] = None,
        p_genai_phishing: Optional[float] = None,
        context_score: float = 0.0,
        has_url: Optional[bool] = None,
        has_file: Optional[bool] = None,
        has_message: Optional[bool] = None
    ) -> float:
        """
        Calculates unified 0-100 risk score.
        Missing modalities are passed as 0.0 with matching availability flag as 0.
        """
        # Determine presence flags
        f_has_url = 1.0 if (has_url if has_url is not None else p_phishing is not None) else 0.0
        f_has_file = 1.0 if (has_file if has_file is not None else p_malware is not None) else 0.0
        f_has_message = 1.0 if (has_message if has_message is not None else p_genai_phishing is not None) else 0.0

        val_phishing = float(p_phishing) if p_phishing is not None else 0.0
        val_malware = float(p_malware) if p_malware is not None else 0.0
        val_genai = float(p_genai_phishing) if p_genai_phishing is not None else 0.0
        val_ctx = max(0.0, min(1.0, float(context_score)))

        # Learned model path
        if self.model is not None and settings.USE_LEARNED_FUSION:
            try:
                input_vector = np.array([[
                    val_phishing,
                    val_malware,
                    val_genai,
                    val_ctx,
                    f_has_url,
                    f_has_file,
                    f_has_message
                ]], dtype=np.float64)

                if hasattr(self.model, "predict_proba"):
                    prob = float(self.model.predict_proba(input_vector)[0, 1])
                elif hasattr(self.model, "decision_function"):
                    # Sigmoid transform for raw decision function
                    df_val = float(self.model.decision_function(input_vector)[0])
                    prob = 1.0 / (1.0 + np.exp(-df_val))
                else:
                    prob = float(self.model.predict(input_vector)[0])

                risk_score = round(max(0.0, min(100.0, prob * 100.0)), 1)
                return risk_score
            except Exception as e:
                logger.warning(f"Inference error in learned fusion model: {e}. Falling back to baseline formula.")

        # Baseline fixed-weight fallback formula
        active_weights = []
        active_vals = []

        if f_has_url == 1.0:
            active_weights.append(settings.WEIGHT_PHISHING)
            active_vals.append(val_phishing)
        if f_has_file == 1.0:
            active_weights.append(settings.WEIGHT_MALWARE)
            active_vals.append(val_malware)
        if f_has_message == 1.0:
            active_weights.append(settings.WEIGHT_MESSAGE)
            active_vals.append(val_genai)

        # Context weight
        ctx_weight = settings.WEIGHT_PHISHING_CONTEXT
        total_model_weight = sum(active_weights) if active_weights else 0.85
        total_weight = total_model_weight + ctx_weight

        if active_weights:
            model_component = sum(w * v for w, v in zip(active_weights, active_vals)) / total_weight
        else:
            model_component = 0.0

        ctx_component = (ctx_weight * val_ctx) / total_weight
        raw_score = 100.0 * (model_component + ctx_component)
        return round(max(0.0, min(100.0, raw_score)), 1)

# Global singleton
fusion_model = FusionModel()
