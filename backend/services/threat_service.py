"""
Threat Analysis Orchestration Service.
Coordinates: Feature Extraction -> Model Inference -> Risk Engine -> SHAP -> Decision Policy -> DB Storage.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import joblib
import pandas as pd
from sqlalchemy.orm import Session

from backend.config import settings
from feature_extraction.feature_contract import URLFeatureContract, PEFeatureContract
from feature_extraction.url_features import extract_url_features_df
from risk_engine.risk_score import (
    risk_engine,
    compute_url_context,
    compute_pe_context
)
from risk_engine.decision_policy import DecisionPolicy
from explainable_ai.phishing_explainer import phishing_explainer
from explainable_ai.malware_explainer import malware_explainer
from explainable_ai.explanation_formatter import ExplanationFormatter
from database.repository import ThreatAnalysisRepository
from backend.schemas.schemas import ThreatAnalysisResponse

# Pre-load champion models
PHISHING_MODEL = joblib.load(settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib")
MALWARE_MODEL = joblib.load(settings.MODELS_DIR / "malware" / "model" / "malware_model.joblib")

class ThreatService:
    @classmethod
    def analyze_url(cls, url: str, db: Session) -> ThreatAnalysisResponse:
        """
        Executes end-to-end URL threat prediction pipeline.
        """
        clean_url = str(url).strip()
        
        # 1. Feature extraction
        features_df = extract_url_features_df([clean_url])
        features_dict = features_df.iloc[0].to_dict()
        
        # 2. Machine learning inference
        phishing_prob = float(PHISHING_MODEL.predict_proba(features_df)[0, 1])
        prediction_label = "Phishing" if phishing_prob >= 0.50 else "Legitimate"
        
        # 3. Contextual evidence & Risk Engine
        ctx_score = compute_url_context(features_dict)
        risk_eval = risk_engine.calculate_url_risk(
            phishing_probability=phishing_prob,
            context_score=ctx_score
        )
        
        # 4. Explainable AI (SHAP)
        attributions = phishing_explainer.explain(features_df, top_k=5)
        formatted_xai = ExplanationFormatter.format_url_explanation(
            attributions=attributions,
            prediction_label=prediction_label,
            probability=phishing_prob
        )
        
        # 5. Decision Policy & Banking Action
        decision_info = DecisionPolicy.get_decision(
            input_type="URL",
            severity=risk_eval.severity
        )
        
        # 6. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        
        db_record = {
            "id": record_id,
            "timestamp": now_utc,
            "input_type": "URL",
            "target": clean_url,
            "file_sha256": None,
            "prediction": prediction_label,
            "probability": round(phishing_prob, 4),
            "risk_score": risk_eval.risk_score,
            "severity": risk_eval.severity.value,
            "decision": decision_info["action"],
            "title": decision_info["title"],
            "recommendation": decision_info["recommendation"],
            "summary": formatted_xai["summary"],
            "top_features": formatted_xai["top_features"],
            "model_version": "v1.0.0",
            "feature_schema_version": URLFeatureContract.SCHEMA_VERSION
        }
        
        repo = ThreatAnalysisRepository(db)
        repo.create(db_record)
        
        # 7. Formulate structured response
        return ThreatAnalysisResponse(
            id=record_id,
            timestamp=now_utc.isoformat(),
            input_type="URL",
            target=clean_url,
            prediction=prediction_label,
            probability=round(phishing_prob, 4),
            risk_score=risk_eval.risk_score,
            severity=risk_eval.severity.value,
            decision=decision_info["action"],
            title=decision_info["title"],
            recommendation=decision_info["recommendation"],
            summary=formatted_xai["summary"],
            reasons=formatted_xai["reasons"],
            top_features=formatted_xai["top_features"],
            model_version="v1.0.0",
            feature_schema_version=URLFeatureContract.SCHEMA_VERSION,
            disclaimer=decision_info["disclaimer"]
        )

    @classmethod
    def analyze_file(
        cls,
        features_df: pd.DataFrame,
        filename: str,
        sha256: str,
        db: Session
    ) -> ThreatAnalysisResponse:
        """
        Executes end-to-end Static PE Malware prediction pipeline.
        """
        features_dict = features_df.iloc[0].to_dict()
        
        # 1. Machine learning inference
        malware_prob = float(MALWARE_MODEL.predict_proba(features_df)[0, 1])
        prediction_label = "Malicious" if malware_prob >= 0.50 else "Benign"
        
        # 2. Contextual evidence & Risk Engine
        ctx_score = compute_pe_context(features_dict)
        risk_eval = risk_engine.calculate_file_risk(
            malware_probability=malware_prob,
            context_score=ctx_score
        )
        
        # 3. Explainable AI (SHAP)
        attributions = malware_explainer.explain(features_df, top_k=5)
        formatted_xai = ExplanationFormatter.format_pe_explanation(
            attributions=attributions,
            prediction_label=prediction_label,
            probability=malware_prob
        )
        
        # 4. Decision Policy & Banking Action
        decision_info = DecisionPolicy.get_decision(
            input_type="FILE",
            severity=risk_eval.severity
        )
        
        # 5. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        
        db_record = {
            "id": record_id,
            "timestamp": now_utc,
            "input_type": "FILE",
            "target": filename,
            "file_sha256": sha256,
            "prediction": prediction_label,
            "probability": round(malware_prob, 4),
            "risk_score": risk_eval.risk_score,
            "severity": risk_eval.severity.value,
            "decision": decision_info["action"],
            "title": decision_info["title"],
            "recommendation": decision_info["recommendation"],
            "summary": formatted_xai["summary"],
            "top_features": formatted_xai["top_features"],
            "model_version": "v1.0.0",
            "feature_schema_version": PEFeatureContract.SCHEMA_VERSION
        }
        
        repo = ThreatAnalysisRepository(db)
        repo.create(db_record)
        
        return ThreatAnalysisResponse(
            id=record_id,
            timestamp=now_utc.isoformat(),
            input_type="FILE",
            target=filename,
            file_sha256=sha256,
            prediction=prediction_label,
            probability=round(malware_prob, 4),
            risk_score=risk_eval.risk_score,
            severity=risk_eval.severity.value,
            decision=decision_info["action"],
            title=decision_info["title"],
            recommendation=decision_info["recommendation"],
            summary=formatted_xai["summary"],
            reasons=formatted_xai["reasons"],
            top_features=formatted_xai["top_features"],
            model_version="v1.0.0",
            feature_schema_version=PEFeatureContract.SCHEMA_VERSION,
            disclaimer=decision_info["disclaimer"]
        )
