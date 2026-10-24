"""
Threat Analysis Orchestration Service.
Coordinates: Feature Extraction -> Model Inference -> Risk Engine -> SHAP -> Decision Policy -> DB Storage.
"""
from typing import Dict, Any, Optional
from datetime import datetime, timezone
import uuid
import logging
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit
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
from backend.services.threat_intel_service import threat_intel_service
from risk_engine.domain_reputation import domain_reputation_service
from backend.services.domain_verification_service import domain_verification_service

logger = logging.getLogger(__name__)


class AnalysisModelUnavailableError(RuntimeError):
    """Raised when an analysis model is required but its artifact is unavailable."""


def _persist_analysis(db: Session, record: Dict[str, Any]) -> bool:
    """Persist history when possible without discarding a completed analysis."""
    try:
        ThreatAnalysisRepository(db).create(record)
        return True
    except Exception:
        # A read-only/full database or transient SQLite lock must not hide the
        # malware verdict already computed for the user.
        try:
            db.rollback()
        except Exception:
            pass
        logger.exception("Could not save analysis history; returning the analysis result without history.")
        return False

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
    @staticmethod
    def _model_url_features(url: str) -> pd.DataFrame:
        """Use stable URL structure for ML; opaque query values are high-noise.

        The complete URL is still used by deterministic context checks and
        displayed in the result. Query parameter names/lexical flags remain
        available through the raw feature row passed to the context engine.
        """
        parsed = urlsplit(url if "://" in url else f"https://{url}")
        structural_url = urlunsplit((parsed.scheme, parsed.netloc, parsed.path, "", ""))
        return extract_url_features_df([structural_url])

    @classmethod
    def analyze_url(cls, url: str, db: Session) -> ThreatAnalysisResponse:
        """
        Executes end-to-end URL threat prediction pipeline.
        """
        clean_url = str(url).strip()
        
        # 1. Validate URL syntax before feature extraction. Plain text (e.g.
        # "hello") is not a URL and must not receive a threat assessment.
        from urllib.parse import urlsplit
        candidate = clean_url if "://" in clean_url else f"https://{clean_url}"
        try:
            parsed_candidate = urlsplit(candidate)
            hostname = parsed_candidate.hostname
            valid_url = (
                parsed_candidate.scheme in {"http", "https"}
                and hostname is not None
                and "." in hostname
                and not hostname.startswith(".")
                and not hostname.endswith(".")
                and " " not in clean_url
            )
        except ValueError:
            valid_url = False
        if not valid_url:
            raise ValueError("Enter a valid URL with a hostname, such as https://example.com.")

        # 2. Feature extraction
        raw_features_df = extract_url_features_df([clean_url])
        features_dict = raw_features_df.iloc[0].to_dict()
        model_features_df = cls._model_url_features(clean_url)
        
        # 2. Machine learning inference. The champion emits the probability used
        # during validation; do not apply an unversioned post-hoc transform here.
        if PHISHING_MODEL is not None:
            raw_prob = float(PHISHING_MODEL.predict_proba(raw_features_df.values)[0, 1])
            structural_prob = float(PHISHING_MODEL.predict_proba(model_features_df.values)[0, 1])
            phishing_prob = raw_prob
        else:
            raw_prob = 0.50
            structural_prob = 0.50
            phishing_prob = 0.50

        # Empirical decision threshold derived on validation split to reduce legitimate false positives
        decision_threshold = getattr(settings, "PHISHING_DECISION_THRESHOLD", 0.55)

        # 3. External Threat Intelligence & Domain Reputation evidence
        threat_intel_res = threat_intel_service.check_url(clean_url)
        threat_intel_dict = threat_intel_res.to_dict()

        domain_rep_res = domain_reputation_service.evaluate(clean_url)
        domain_rep_dict = domain_rep_res.to_dict()
        domain_verification = domain_verification_service.evaluate(clean_url).to_dict()

        # Opaque search/tracking query values can dominate lexical features.
        # For ranked domains with no suspicious URL terms, use the stable
        # hostname+path estimate; keep full-URL scoring for every other case.
        explain_features_df = raw_features_df
        if domain_rep_dict.get("is_established") and not features_dict.get("ContainsSuspiciousKeyword", 0.0):
            phishing_prob = structural_prob
            explain_features_df = model_features_df
        
        # 4. Contextual evidence & Multi-Evidence Risk Fusion
        ctx_score = compute_url_context(features_dict, domain_rep_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="URL",
            p_phishing=phishing_prob,
            context_score=ctx_score,
            threat_intel=threat_intel_dict,
            domain_reputation=domain_rep_dict,
            domain_verification=domain_verification,
            url_features=features_dict
        )
        
        # Harmonize prediction label with multi-evidence risk evaluation
        if risk_eval.final_assessment == "MALICIOUS":
            prediction_label = "Phishing"
        elif risk_eval.final_assessment == "LIKELY LEGITIMATE":
            prediction_label = "Legitimate"
        elif phishing_prob >= decision_threshold:
            # Preserve the model's class prediction while the separate final
            # assessment communicates that evidence is not conclusive.
            prediction_label = "Phishing"
        else:
            prediction_label = "Suspicious / Unknown"

        # 5. Explainable AI (SHAP on the 20 URL model features)
        attributions = phishing_explainer.explain(explain_features_df, top_k=5)
        formatted_xai = ExplanationFormatter.format_url_explanation(
            attributions=attributions,
            prediction_label=prediction_label,
            probability=phishing_prob,
            threat_intel=threat_intel_dict,
            domain_reputation=domain_rep_dict,
            final_assessment=risk_eval.final_assessment
        )
        
        # 6. Decision Policy & Banking Action
        decision_info = DecisionPolicy.get_decision(
            input_type="URL",
            severity=risk_eval.severity,
            final_assessment=risk_eval.final_assessment
        )
        
        # Determine accurate prediction likelihood and descriptive label
        if prediction_label == "Phishing":
            pred_likelihood = round(phishing_prob, 4)
            pred_label = "Phishing Likelihood"
        elif prediction_label == "Suspicious / Unknown":
            pred_likelihood = round(phishing_prob, 4)
            pred_label = "Model Phishing Likelihood"
        else:
            pred_likelihood = round(1.0 - phishing_prob, 4)
            pred_label = "Legitimate Likelihood"

        score_breakdown = dict(risk_eval.risk_score_breakdown)
        score_breakdown.update({
            "model_input": "hostname and path (query excluded)" if explain_features_df is model_features_df else "complete URL",
            "displayed_likelihood": pred_likelihood,
            "displayed_likelihood_label": pred_label,
            "contextual_risk_percent": round(ctx_score * 100.0, 1),
        })

        # 7. Database Persistence
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
            "detector_probabilities": {
                "p_phishing": round(phishing_prob, 4),
                "p_raw_phishing": round(raw_prob, 4),
                "context_score": round(ctx_score, 4),
                "domain_verification": domain_verification,
                "domain_reputation": domain_rep_dict,
                "threat_intel": threat_intel_dict,
                "final_assessment": risk_eval.final_assessment,
                "risk_score_breakdown": score_breakdown
            },
            "context_score": round(ctx_score, 4),
            "model_version": "v1.0.0",
            "feature_schema_version": URLFeatureContract.SCHEMA_VERSION
        }
        
        repo = ThreatAnalysisRepository(db)
        repo.create(db_record)
        
        # 8. Formulate structured response
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
            detector_probabilities={
                "p_phishing": round(phishing_prob, 4),
                "p_raw_phishing": round(raw_prob, 4),
                "context_score": round(ctx_score, 4)
            },
            context_score=round(ctx_score, 4),
            prediction_likelihood=pred_likelihood,
            prediction_likelihood_label=pred_label,
            threat_intel=threat_intel_dict,
            domain_reputation=domain_rep_dict,
            domain_verification=domain_verification,
            final_assessment=risk_eval.final_assessment,
            evidence_breakdown=formatted_xai.get("evidence_breakdown"),
            risk_score_breakdown=score_breakdown
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
        features_df = PEFeatureContract.validate_and_align(features_df)
        features_dict = features_df.iloc[0].to_dict()
        
        # 1. Machine learning inference
        if MALWARE_MODEL is None:
            raise AnalysisModelUnavailableError("Malware detection model is unavailable.")
        if not hasattr(MALWARE_MODEL, "predict_proba"):
            raise AnalysisModelUnavailableError("Malware detection model does not support probability inference.")
        classes = list(getattr(MALWARE_MODEL, "classes_", []))
        if 1 not in classes:
            raise AnalysisModelUnavailableError("Malware model has no malicious class (class 1).")
        malware_class_index = classes.index(1)
        malware_prob = float(MALWARE_MODEL.predict_proba(features_df)[0, malware_class_index])
        if not 0.0 <= malware_prob <= 1.0:
            raise ValueError("Malware model returned an invalid probability.")
        prediction_label = "Malicious" if malware_prob >= 0.50 else "Benign"
        
        # 2. Contextual evidence & Risk Engine
        ctx_score = compute_pe_context(features_dict)
        risk_eval = risk_engine.calculate_unified_risk(
            input_type="FILE",
            p_malware=malware_prob,
            context_score=ctx_score
        )
        
        # 3. Explainable AI (SHAP)
        try:
            attributions = malware_explainer.explain(features_df, top_k=5)
        except Exception:
            logger.exception("Malware explanation failed; returning the model prediction without SHAP details.")
            attributions = []
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
        
        # Determine accurate prediction likelihood and descriptive label
        if prediction_label == "Malicious":
            pred_likelihood = round(malware_prob, 4)
            pred_label = "Malware Likelihood"
        else:
            pred_likelihood = round(1.0 - malware_prob, 4)
            pred_label = "Legitimate Likelihood"

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
            "detector_probabilities": {"p_malware": round(malware_prob, 4), "context_score": round(ctx_score, 4)},
            "context_score": round(ctx_score, 4),
            "model_version": "v1.0.0",
            "feature_schema_version": PEFeatureContract.SCHEMA_VERSION
        }
        
        history_saved = _persist_analysis(db, db_record)
        
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
            detector_probabilities={"p_malware": round(malware_prob, 4), "context_score": round(ctx_score, 4)},
            context_score=round(ctx_score, 4),
            prediction_likelihood=pred_likelihood,
            prediction_likelihood_label=pred_label,
            history_saved=history_saved
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
        
        # Determine accurate prediction likelihood and descriptive label
        if prediction_label in ["ai_phishing", "human_phishing"]:
            pred_likelihood = round(threat_prob, 4)
            pred_label = "Phishing Likelihood"
        else:
            pred_likelihood = round(1.0 - threat_prob, 4)
            pred_label = "Legitimate Likelihood"

        # 6. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        target_display = clean_text[:120] + "..." if len(clean_text) > 120 else clean_text
        
        detector_probs["context_score"] = round(ctx_score, 4)

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
            "context_score": round(ctx_score, 4),
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
            context_score=round(ctx_score, 4),
            prediction_likelihood=pred_likelihood,
            prediction_likelihood_label=pred_label,
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
                    raw_src = float(PHISHING_MODEL.predict_proba(features_src_df.values)[0, 1])
                    p_src = raw_src
                except Exception as e:
                    logger.warning(f"Error evaluating source_url phishing: {e}")
            if clean_download_url:
                try:
                    features_dl_df = extract_url_features_df([clean_download_url])
                    raw_dl = float(PHISHING_MODEL.predict_proba(features_dl_df.values)[0, 1])
                    p_dl = raw_dl
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

        # Determine accurate prediction likelihood and descriptive label
        if prediction_label in ["Phishing / Suspicious", "High-Risk Executable", "Medium-Risk File"]:
            pred_likelihood = round(max_phishing_prob, 4) if max_phishing_prob >= 0.50 else round(ctx_score, 4)
            pred_label = "Phishing Likelihood" if max_phishing_prob >= 0.50 else "Threat Likelihood"
        else:
            pred_likelihood = round(1.0 - max_phishing_prob, 4)
            pred_label = "Legitimate Likelihood"

        # 6. Database Persistence
        record_id = str(uuid.uuid4())
        now_utc = datetime.now(timezone.utc)
        
        detector_probs = {
            "p_source_phishing": round(p_src, 4),
            "p_download_phishing": round(p_dl, 4),
            "max_phishing_prob": round(max_phishing_prob, 4),
            "context_modifier": round(ctx_score, 4),
            "context_score": round(ctx_score, 4)
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
            "context_score": round(ctx_score, 4),
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
            context_score=round(ctx_score, 4),
            prediction_likelihood=pred_likelihood,
            prediction_likelihood_label=pred_label,
            download_source_url=clean_source_url,
            download_url=clean_download_url,
            model_version="v1.0.0",
            feature_schema_version=DownloadFeatureContract.SCHEMA_VERSION,
            disclaimer=decision_info["disclaimer"]
        )
