"""
Threat Analysis Orchestration Service.
Coordinates: Feature Extraction -> Model Inference -> Risk Engine -> SHAP -> Decision Policy -> DB Storage.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import logging
from pathlib import Path
import joblib
import pandas as pd
from sqlalchemy.orm import Session

from backend.config import settings
from feature_extraction.feature_contract import (
    URLFeatureContract,
    PEFeatureContract,
    MessageFeatureContract,
    DownloadFeatureContract
)
from feature_extraction.url_features import extract_url_features_df
from feature_extraction.message_features import extract_message_features_df
from feature_extraction.download_features import (
    extract_download_features_dict,
    extract_download_features_df,
    get_extension_risk_tier
)
from risk_engine.risk_score import (
    risk_engine,
    compute_url_context,
    compute_pe_context,
    compute_message_context,
    compute_download_context
)
from risk_engine.decision_policy import DecisionPolicy
from explainable_ai.phishing_explainer import phishing_explainer
from explainable_ai.malware_explainer import malware_explainer
from explainable_ai.content_explainer import content_explainer
from explainable_ai.explanation_formatter import ExplanationFormatter
from database.repository import ThreatAnalysisRepository
from backend.schemas.schemas import ThreatAnalysisResponse

logger = logging.getLogger(__name__)

# Pre-load champion models with graceful handling
PHISHING_MODEL = None
MALWARE_MODEL = None
MESSAGE_STYLO_MODEL = None

try:
    p_path = settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib"
    if p_path.exists():
        PHISHING_MODEL = joblib.load(p_path)
except Exception as e:
    logger.warning(f"Could not preload phishing model: {e}")

try:
    m_path = settings.MODELS_DIR / "malware" / "model" / "malware_model.joblib"
    if m_path.exists():
        MALWARE_MODEL = joblib.load(m_path)
except Exception as e:
    logger.warning(f"Could not preload malware model: {e}")

try:
    s_path = settings.MODELS_DIR / "message_content" / "stylometric" / "model.joblib"
    if s_path.exists():
        MESSAGE_STYLO_MODEL = joblib.load(s_path)
except Exception as e:
    logger.warning(f"Could not preload message stylometric model: {e}")

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
        if PHISHING_MODEL is not None:
            phishing_prob = float(PHISHING_MODEL.predict_proba(features_df.values)[0, 1])
        else:
            phishing_prob = 0.50
        prediction_label = "Phishing" if phishing_prob >= 0.50 else "Legitimate"
        
        # 3. Contextual evidence & Risk Engine
        ctx_score = compute_url_context(features_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="URL",
            p_phishing=phishing_prob,
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
            "highlighted_spans": None,
            "detector_probabilities": {"p_phishing": round(phishing_prob, 4)},
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
            disclaimer=decision_info["disclaimer"],
            detector_probabilities={"p_phishing": round(phishing_prob, 4)}
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
        if MALWARE_MODEL is not None:
            malware_prob = float(MALWARE_MODEL.predict_proba(features_df.values)[0, 1])
        else:
            malware_prob = 0.50
        prediction_label = "Malicious" if malware_prob >= 0.50 else "Benign"
        
        # 2. Contextual evidence & Risk Engine
        ctx_score = compute_pe_context(features_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="FILE",
            p_malware=malware_prob,
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
            "highlighted_spans": None,
            "detector_probabilities": {"p_malware": round(malware_prob, 4)},
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
            disclaimer=decision_info["disclaimer"],
            detector_probabilities={"p_malware": round(malware_prob, 4)}
        )

    @classmethod
    def analyze_message(cls, text: str, db: Session) -> ThreatAnalysisResponse:
        """
        Executes end-to-end GenAI and Human Phishing Message prediction pipeline.
        """
        clean_text = str(text).strip()
        
        # 1. Feature extraction
        features_df = extract_message_features_df([clean_text])
        features_dict = features_df.iloc[0].to_dict()
        
        # 2. Machine learning inference across branches
        detector_probs = {}
        if MESSAGE_STYLO_MODEL is not None:
            try:
                probs = MESSAGE_STYLO_MODEL.predict_proba(features_df.values)[0]
                if len(probs) >= 3:
                    p_legit, p_human, p_ai = float(probs[0]), float(probs[1]), float(probs[2])
                elif len(probs) == 2:
                    p_legit, p_human, p_ai = float(probs[0]), float(probs[1]), 0.0
                else:
                    p_legit, p_human, p_ai = 0.5, 0.5, 0.0
                
                detector_probs["p_legitimate"] = round(p_legit, 4)
                detector_probs["p_human_phishing"] = round(p_human, 4)
                detector_probs["p_ai_phishing"] = round(p_ai, 4)
                
                threat_prob = round(p_human + p_ai, 4)
                if p_ai >= p_human and p_ai >= p_legit:
                    prediction_label = "ai_phishing"
                elif p_human >= p_legit:
                    prediction_label = "human_phishing"
                else:
                    prediction_label = "legitimate"
            except Exception as e:
                logger.warning(f"Stylometric model inference error: {e}")
                threat_prob = 0.50
                prediction_label = "human_phishing"
        else:
            # Heuristic estimate based on context indicators
            ctx = compute_message_context(features_dict)
            threat_prob = round(max(0.05, min(0.95, ctx * 0.90 + 0.10 if ctx > 0 else 0.05)), 4)
            prediction_label = "ai_phishing" if features_dict.get("SentenceLengthVariance", 0) < 5 and threat_prob > 0.5 else ("human_phishing" if threat_prob >= 0.5 else "legitimate")
            detector_probs["p_genai_phishing"] = threat_prob

        # 3. Contextual evidence & Risk Engine
        ctx_score = compute_message_context(features_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="MESSAGE",
            p_genai_phishing=threat_prob,
            context_score=ctx_score
        )
        
        # 4. Explainable AI (SHAP + Highlight Spans)
        xai_res = content_explainer.explain(text=clean_text, features_df=features_df, top_k=5)
        top_features = xai_res["top_features"]
        highlighted_spans = xai_res["highlighted_spans"]
        
        formatted_xai = ExplanationFormatter.format_message_explanation(
            attributions=top_features,
            prediction_label=prediction_label,
            probability=threat_prob
        )
        
        # 5. Decision Policy & Banking Action
        decision_info = DecisionPolicy.get_decision(
            input_type="MESSAGE",
            severity=risk_eval.severity
        )
        
        # 6. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        target_display = clean_text[:120] + "..." if len(clean_text) > 120 else clean_text
        
        db_record = {
            "id": record_id,
            "timestamp": now_utc,
            "input_type": "MESSAGE",
            "target": target_display,
            "file_sha256": None,
            "prediction": prediction_label,
            "probability": round(threat_prob, 4),
            "risk_score": risk_eval.risk_score,
            "severity": risk_eval.severity.value,
            "decision": decision_info["action"],
            "title": decision_info["title"],
            "recommendation": decision_info["recommendation"],
            "summary": formatted_xai["summary"],
            "top_features": formatted_xai["top_features"],
            "highlighted_spans": highlighted_spans,
            "detector_probabilities": detector_probs,
            "model_version": "v1.0.0",
            "feature_schema_version": MessageFeatureContract.SCHEMA_VERSION
        }
        
        repo = ThreatAnalysisRepository(db)
        repo.create(db_record)
        
        # 7. Formulate structured response
        return ThreatAnalysisResponse(
            id=record_id,
            timestamp=now_utc.isoformat(),
            input_type="MESSAGE",
            target=target_display,
            prediction=prediction_label,
            probability=round(threat_prob, 4),
            risk_score=risk_eval.risk_score,
            severity=risk_eval.severity.value,
            decision=decision_info["action"],
            title=decision_info["title"],
            recommendation=decision_info["recommendation"],
            summary=formatted_xai["summary"],
            reasons=formatted_xai["reasons"],
            top_features=formatted_xai["top_features"],
            highlighted_spans=highlighted_spans,
            detector_probabilities=detector_probs,
            model_version="v1.0.0",
            feature_schema_version=MessageFeatureContract.SCHEMA_VERSION,
            disclaimer=decision_info["disclaimer"]
        )

    @classmethod
    def analyze_download(
        cls,
        filename: str,
        file_extension: str,
        source_url: str,
        download_url: str,
        db: Session
    ) -> ThreatAnalysisResponse:
        """
        Executes end-to-end file download metadata threat prediction pipeline.
        Reuses existing URL phishing models and Risk Engine without handling file binary content.
        """
        clean_filename = str(filename or "").strip()
        clean_ext = str(file_extension or "").strip()
        clean_source_url = str(source_url or "").strip()
        clean_download_url = str(download_url or "").strip()

        # 1. Feature extraction & URL evidence computation
        p_src = 0.0
        p_dl = 0.0
        features_src_df = None
        features_dl_df = None

        if PHISHING_MODEL is not None:
            if clean_source_url:
                try:
                    features_src_df = extract_url_features_df([clean_source_url])
                    p_src = float(PHISHING_MODEL.predict_proba(features_src_df.values)[0, 1])
                except Exception as e:
                    logger.warning(f"Error evaluating source_url phishing: {e}")
            if clean_download_url:
                try:
                    features_dl_df = extract_url_features_df([clean_download_url])
                    p_dl = float(PHISHING_MODEL.predict_proba(features_dl_df.values)[0, 1])
                except Exception as e:
                    logger.warning(f"Error evaluating download_url phishing: {e}")

        max_phishing_prob = max(p_src, p_dl)
        tier = get_extension_risk_tier(clean_ext)
        
        # Extract structured download features
        features_dict = extract_download_features_dict(
            filename=clean_filename,
            file_extension=clean_ext,
            source_url=clean_source_url,
            download_url=clean_download_url,
            source_phishing_prob=p_src,
            download_phishing_prob=p_dl
        )
        
        # 2. Machine learning prediction label
        if max_phishing_prob >= 0.50:
            prediction_label = "Phishing / Suspicious"
        elif tier >= 2.0:
            prediction_label = "High-Risk Executable"
        elif tier >= 1.0:
            prediction_label = "Medium-Risk File"
        else:
            prediction_label = "Legitimate / Safe"

        # 3. Contextual evidence & Risk Engine
        ctx_score = compute_download_context(features_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="DOWNLOAD",
            p_phishing=max_phishing_prob,
            context_score=ctx_score
        )

        # 4. Explainable AI (SHAP based on higher-risk URL origin + download context)
        eval_df = features_dl_df if (p_dl >= p_src and features_dl_df is not None) else (features_src_df if features_src_df is not None else extract_url_features_df([clean_source_url or clean_download_url or "http://unknown"]))
        attributions = phishing_explainer.explain(eval_df, top_k=5)
        
        formatted_xai = ExplanationFormatter.format_download_explanation(
            attributions=attributions,
            prediction_label=prediction_label,
            probability=max_phishing_prob,
            severity_label=risk_eval.severity.value,
            filename=clean_filename,
            file_extension=clean_ext,
            source_url=clean_source_url,
            download_url=clean_download_url,
            is_cross_domain=bool(features_dict.get("IsCrossDomain", 0.0) == 1.0),
            extension_risk_tier=tier
        )

        # 5. Decision Policy & Banking Action
        decision_info = DecisionPolicy.get_decision(
            input_type="DOWNLOAD",
            severity=risk_eval.severity
        )

        # 6. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        
        detector_probs = {
            "p_source_phishing": round(p_src, 4),
            "p_download_phishing": round(p_dl, 4),
            "max_phishing_prob": round(max_phishing_prob, 4),
            "context_modifier": round(ctx_score, 4)
        }

        db_record = {
            "id": record_id,
            "timestamp": now_utc,
            "input_type": "DOWNLOAD",
            "target": clean_filename,
            "file_sha256": None,
            "download_source_url": clean_source_url,
            "download_url": clean_download_url,
            "prediction": prediction_label,
            "probability": round(max_phishing_prob, 4),
            "risk_score": risk_eval.risk_score,
            "severity": risk_eval.severity.value,
            "decision": decision_info["action"],
            "title": decision_info["title"],
            "recommendation": decision_info["recommendation"],
            "summary": formatted_xai["summary"],
            "top_features": formatted_xai["top_features"],
            "highlighted_spans": None,
            "detector_probabilities": detector_probs,
            "model_version": "v1.0.0",
            "feature_schema_version": DownloadFeatureContract.SCHEMA_VERSION
        }

        repo = ThreatAnalysisRepository(db)
        repo.create(db_record)

        # 7. Formulate structured response
        return ThreatAnalysisResponse(
            id=record_id,
            timestamp=now_utc.isoformat(),
            input_type="DOWNLOAD",
            target=clean_filename,
            prediction=prediction_label,
            probability=round(max_phishing_prob, 4),
            risk_score=risk_eval.risk_score,
            severity=risk_eval.severity.value,
            decision=decision_info["action"],
            title=decision_info["title"],
            recommendation=decision_info["recommendation"],
            summary=formatted_xai["summary"],
            reasons=formatted_xai["reasons"],
            top_features=formatted_xai["top_features"],
            highlighted_spans=None,
            detector_probabilities=detector_probs,
            download_source_url=clean_source_url,
            download_url=clean_download_url,
            model_version="v1.0.0",
            feature_schema_version=DownloadFeatureContract.SCHEMA_VERSION,
            disclaimer=decision_info["disclaimer"]
        )
