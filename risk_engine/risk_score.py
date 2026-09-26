"""
Unified Risk Score Calculation Engine.
Calculates unified 0-100 risk score based on model evidence and validated contextual indicators.
Strictly uses input-specific configurations (URL vs File).
"""
from dataclasses import dataclass
from typing import Dict, Any, Optional
from risk_engine.thresholds import ThresholdConfig, SeverityLevel
from backend.config import settings

@dataclass
class RiskAssessment:
    input_type: str
    risk_score: float
    severity: SeverityLevel
    model_probability: float
    context_score: float
    weights: Dict[str, float]
    threat_intel: Optional[Dict[str, Any]] = None
    domain_reputation: Optional[Dict[str, Any]] = None
    final_assessment: Optional[str] = None

def compute_url_context(
    features: Dict[str, float],
    domain_reputation: Optional[Dict[str, Any]] = None
) -> float:
    """
    Computes a contextual risk modifier [0.0, 1.0] from URL static properties:
    - IP Host (+0.40)
    - Suspicious Banking Keywords (+0.30)
    - High Subdomain Depth >= 2 (+0.20)
    - No HTTPS (+0.10)
    """
    ctx = 0.0
    if features.get("IsDomainIP", 0.0) == 1.0:
        ctx += 0.40
    if features.get("ContainsSuspiciousKeyword", 0.0) == 1.0:
        ctx += 0.30
    if features.get("NoOfSubDomain", 0.0) >= 2.0:
        ctx += 0.20
    if features.get("IsHTTPS", 1.0) == 0.0:
        ctx += 0.10
    if domain_reputation and not domain_reputation.get("is_established"):
        # An unranked domain remains unverified even if registration/TLS checks
        # pass; those checks establish infrastructure, not benign content.
        ctx += 0.10
    return round(min(1.0, ctx), 4)

def compute_pe_context(features: Dict[str, float]) -> float:
    """
    Computes a contextual risk modifier [0.0, 1.0] from PE static properties:
    - Zero or single section count (+0.40)
    - Creation year anomaly (< 1995 or > 2030) (+0.30)
    - Missing or zero size of code (+0.30)
    """
    ctx = 0.0
    num_sections = features.get("NumberOfSections", 0.0)
    if num_sections <= 1.0:
        ctx += 0.40
    year = features.get("CreationYear", 2000.0)
    if year < 1995.0 or year > 2030.0:
        ctx += 0.30
    if features.get("SizeOfCode", 1.0) == 0.0:
        ctx += 0.30
    return round(min(1.0, ctx), 4)

def compute_message_context(features: Dict[str, float]) -> float:
    """
    Computes a contextual risk modifier [0.0, 1.0] from message stylometric properties:
    - Presence of coercive urgency lexicon (+0.35)
    - Credential request keywords (+0.35)
    - Generic impersonal greeting (+0.20)
    - Embedded suspicious links (+0.10)
    """
    ctx = 0.0
    if features.get("UrgencyWordCount", 0.0) >= 1.0:
        ctx += 0.35
    if features.get("CredentialRequestCount", 0.0) >= 1.0:
        ctx += 0.35
    if features.get("GreetingGenericFlag", 0.0) == 1.0:
        ctx += 0.20
    if features.get("URLCount", 0.0) >= 1.0:
        ctx += 0.10
    return round(min(1.0, ctx), 4)

def compute_download_context(features: Dict[str, float]) -> float:
    """
    Computes a contextual risk modifier [0.0, 1.0] from file download metadata:
    - High-risk extension tier == 2.0 (+0.40) or Medium-risk tier == 1.0 (+0.20)
    - Cross-domain redirect discrepancy (+0.30)
    - Suspicious banking/credential keywords in filename (+0.20)
    - High filename entropy or length (> 3.5 entropy or > 40 chars) (+0.10)
    """
    ctx = 0.0
    tier = features.get("ExtensionRiskTier", 0.0)
    if tier >= 2.0:
        ctx += 0.40
    elif tier >= 1.0:
        ctx += 0.20
        
    if features.get("IsCrossDomain", 0.0) == 1.0:
        ctx += 0.30
        
    if features.get("ContainsSuspiciousKeyword", 0.0) == 1.0:
        ctx += 0.20
        
    if features.get("FilenameEntropy", 0.0) > 3.5 or features.get("FilenameLength", 0.0) > 40:
        ctx += 0.10
        
    return round(min(1.0, ctx), 4)

class RiskAnalysisEngine:
    def __init__(
        self,
        weight_phishing: float = 0.85,
        weight_phishing_context: float = 0.15,
        weight_malware: float = 0.85,
        weight_malware_context: float = 0.15,
        weight_message: float = 0.85,
        weight_message_context: float = 0.15
    ):
        total_url = weight_phishing + weight_phishing_context
        self.w_url_model = weight_phishing / total_url
        self.w_url_context = weight_phishing_context / total_url
        
        total_file = weight_malware + weight_malware_context
        self.w_file_model = weight_malware / total_file
        self.w_file_context = weight_malware_context / total_file

        total_msg = weight_message + weight_message_context
        self.w_msg_model = weight_message / total_msg
        self.w_msg_context = weight_message_context / total_msg
        
    def calculate_url_risk(
        self,
        phishing_probability: float,
        context_score: float = 0.0,
        threat_intel: Optional[Dict[str, Any]] = None,
        domain_reputation: Optional[Dict[str, Any]] = None,
        domain_verification: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        p_clamped = max(0.0, min(1.0, float(phishing_probability)))
        c_clamped = max(0.0, min(1.0, float(context_score)))
        
        verification = domain_verification or {}
        age_days = verification.get("domain_age_days")
        is_established = bool(domain_reputation and domain_reputation.get("is_established"))
        confirmed_threat = bool(threat_intel and threat_intel.get("is_threat"))

        # Unified Risk fuses the learned URL prediction, static URL signals,
        # and supporting domain evidence. Model probability remains separate.
        feature_risk = 0.0
        if c_clamped >= 0.80:
            feature_risk = 72.0
        elif c_clamped >= 0.60:
            feature_risk = 58.0
        elif c_clamped >= 0.40:
            feature_risk = 46.0
        elif c_clamped >= 0.20:
            feature_risk = 34.0
        elif c_clamped >= 0.10:
            feature_risk = 24.0

        # Registration/DNS/TLS are corroborating signals, not a safety verdict.
        domain_risk = 0.0
        if not is_established:
            domain_risk += 12.0
        if isinstance(age_days, (int, float)) and age_days < 30:
            domain_risk += 12.0
        if verification.get("registration_status") in {"not_found", "reserved"}:
            domain_risk += 10.0
        elif verification.get("registration_status") in {"unavailable", "unsupported", "invalid"}:
            domain_risk += 4.0
        if verification.get("dns_status") in {"no_records", "unavailable"}:
            domain_risk += 8.0
        if verification.get("tls_status") == "invalid":
            domain_risk += 8.0
        elif verification.get("tls_status") in {"unavailable", "not_checked_no_dns"}:
            domain_risk += 3.0

        combined = (100.0 * (self.w_url_model * p_clamped + self.w_url_context * c_clamped))
        combined = (0.65 * combined) + (0.25 * feature_risk) + (0.10 * min(30.0, domain_risk))
        if (is_established and verification.get("registration_status") == "registered"
                and verification.get("dns_status") == "resolves" and verification.get("tls_status") == "valid"):
            combined -= 2.0
        elif not is_established:
            # Unranked domains with ordinary structure start in the caution
            # band, but this floor alone never calls them malicious.
            combined = max(15.0, combined)
        risk_score = max(0.0, min(100.0, combined))
        if confirmed_threat:
            risk_score = max(90.0, risk_score)
        risk_score = round(risk_score, 1)

        # Agreed score bands: 0–29 low, 30–49 medium, 50–89 high, 90–100 critical.
        if risk_score < 30.0:
            severity = SeverityLevel.LOW
        elif risk_score < 50.0:
            severity = SeverityLevel.MEDIUM
        elif risk_score < 90.0:
            severity = SeverityLevel.HIGH
        else:
            severity = SeverityLevel.CRITICAL

        strong_url_evidence = c_clamped >= 0.60 or p_clamped >= 0.80
        if confirmed_threat or risk_score >= 90.0 or (strong_url_evidence and risk_score >= 70.0):
            final_assessment = "MALICIOUS"
        elif risk_score >= 50.0:
            final_assessment = "SUSPICIOUS / UNKNOWN"
        elif (is_established and verification.get("registration_status") == "registered"
              and verification.get("dns_status") == "resolves" and verification.get("tls_status") == "valid"
              and p_clamped < getattr(settings, "PHISHING_DECISION_THRESHOLD", 0.55) and c_clamped <= 0.30):
            final_assessment = "LIKELY LEGITIMATE"
        elif risk_score < 30.0 and is_established and c_clamped < 0.20:
            final_assessment = "LIKELY LEGITIMATE"
        else:
            final_assessment = "SUSPICIOUS / UNKNOWN"
        
        return RiskAssessment(
            input_type="URL",
            risk_score=risk_score,
            severity=severity,
            model_probability=round(p_clamped, 4),
            context_score=round(c_clamped, 4),
            weights={"model": round(self.w_url_model, 4), "context": round(self.w_url_context, 4)},
            threat_intel=threat_intel,
            domain_reputation=domain_reputation,
            final_assessment=final_assessment
        )
        
    def calculate_file_risk(
        self,
        malware_probability: float,
        context_score: float = 0.0
    ) -> RiskAssessment:
        p_clamped = max(0.0, min(1.0, float(malware_probability)))
        c_clamped = max(0.0, min(1.0, float(context_score)))
        
        raw_score = 100.0 * (self.w_file_model * p_clamped + self.w_file_context * c_clamped)
        risk_score = round(max(0.0, min(100.0, raw_score)), 1)
        severity = ThresholdConfig.get_severity(risk_score)
        
        return RiskAssessment(
            input_type="FILE",
            risk_score=risk_score,
            severity=severity,
            model_probability=round(p_clamped, 4),
            context_score=round(c_clamped, 4),
            weights={"model": round(self.w_file_model, 4), "context": round(self.w_file_context, 4)}
        )

    def calculate_message_risk(
        self,
        message_probability: float,
        context_score: float = 0.0
    ) -> RiskAssessment:
        p_clamped = max(0.0, min(1.0, float(message_probability)))
        c_clamped = max(0.0, min(1.0, float(context_score)))
        
        raw_score = 100.0 * (self.w_msg_model * p_clamped + self.w_msg_context * c_clamped)
        risk_score = round(max(0.0, min(100.0, raw_score)), 1)
        severity = ThresholdConfig.get_severity(risk_score)
        
        return RiskAssessment(
            input_type="MESSAGE",
            risk_score=risk_score,
            severity=severity,
            model_probability=round(p_clamped, 4),
            context_score=round(c_clamped, 4),
            weights={"model": round(self.w_msg_model, 4), "context": round(self.w_msg_context, 4)}
        )

    def calculate_download_risk(
        self,
        source_url: str,
        download_url: str,
        features_dict: Dict[str, float]
    ) -> RiskAssessment:
        """
        Evaluates download risk by running the URL phishing model on both source_url and download_url,
        taking max threat probability and fusing with download contextual signals.
        """
        import joblib
        from feature_extraction.url_features import extract_url_features_df
        
        # Load phishing champion model if present
        p_model_path = settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib"
        p_src = 0.0
        p_dl = 0.0
        
        if p_model_path.exists():
            try:
                m = joblib.load(p_model_path)
                if source_url:
                    f_src = extract_url_features_df([source_url])
                    p_src = float(m.predict_proba(f_src.values)[0, 1])
                if download_url:
                    f_dl = extract_url_features_df([download_url])
                    p_dl = float(m.predict_proba(f_dl.values)[0, 1])
            except Exception:
                pass
                
        max_p = max(p_src, p_dl)
        ctx_score = compute_download_context(features_dict)
        
        # Update features dict with genuine URL probabilities
        features_dict["SourcePhishingProb"] = round(p_src, 4)
        features_dict["DownloadPhishingProb"] = round(p_dl, 4)
        features_dict["MaxPhishingProb"] = round(max_p, 4)
        
        return self.calculate_unified_risk(
            input_type="DOWNLOAD",
            p_phishing=max_p,
            context_score=ctx_score
        )

    def calculate_unified_risk(
        self,
        input_type: str,
        p_phishing: Optional[float] = None,
        p_malware: Optional[float] = None,
        p_genai_phishing: Optional[float] = None,
        context_score: float = 0.0,
        threat_intel: Optional[Dict[str, Any]] = None,
        domain_reputation: Optional[Dict[str, Any]] = None,
        domain_verification: Optional[Dict[str, Any]] = None
    ) -> RiskAssessment:
        """
        Calculates unified risk using learned FusionModel if available,
        or dynamically delegating to modality-specific assessment.
        """
        itype = input_type.upper()
        if itype == "URL" and p_phishing is not None:
            return self.calculate_url_risk(
                phishing_probability=p_phishing,
                context_score=context_score,
                threat_intel=threat_intel,
                domain_reputation=domain_reputation,
                domain_verification=domain_verification
            )

        from risk_engine.fusion_model import fusion_model
        
        risk_score = fusion_model.predict_risk(
            p_phishing=p_phishing,
            p_malware=p_malware,
            p_genai_phishing=p_genai_phishing,
            context_score=context_score,
            has_url=(p_phishing is not None),
            has_file=(p_malware is not None),
            has_message=(p_genai_phishing is not None)
        )
        
        severity = ThresholdConfig.get_severity(risk_score)
        primary_prob = (
            p_genai_phishing if p_genai_phishing is not None
            else (p_phishing if p_phishing is not None else (p_malware if p_malware is not None else 0.0))
        )
        
        return RiskAssessment(
            input_type=input_type.upper(),
            risk_score=risk_score,
            severity=severity,
            model_probability=round(float(primary_prob), 4),
            context_score=round(float(context_score), 4),
            weights={"fusion": 1.0} if fusion_model.is_loaded else {"model": 0.85, "context": 0.15}
        )

risk_engine = RiskAnalysisEngine(
    weight_phishing=settings.WEIGHT_PHISHING,
    weight_phishing_context=settings.WEIGHT_PHISHING_CONTEXT,
    weight_malware=settings.WEIGHT_MALWARE,
    weight_malware_context=settings.WEIGHT_MALWARE_CONTEXT,
    weight_message=settings.WEIGHT_MESSAGE,
    weight_message_context=settings.WEIGHT_MESSAGE_CONTEXT
)
