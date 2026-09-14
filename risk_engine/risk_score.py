"""
Unified Risk Score Calculation Engine.
Calculates unified 0-100 risk score based on model evidence and validated contextual indicators.
Strictly adapts to the input type (URL vs File).
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

def compute_url_context(features: Dict[str, float]) -> float:
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
    return min(1.0, ctx)

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
    return min(1.0, ctx)

class RiskAnalysisEngine:
    def __init__(
        self,
        weight_model: float = 0.85,
        weight_context: float = 0.15
    ):
        # Normalize weights
        total = weight_model + weight_context
        self.w_model = weight_model / total
        self.w_context = weight_context / total
        
    def calculate_url_risk(
        self,
        phishing_probability: float,
        context_score: float = 0.0
    ) -> RiskAssessment:
        """
        Calculates unified risk score for URL threat analysis.
        Formula: 100 * [w_model * P(phishing) + w_context * C(context)]
        """
        p_clamped = max(0.0, min(1.0, float(phishing_probability)))
        c_clamped = max(0.0, min(1.0, float(context_score)))
        
        raw_score = 100.0 * (self.w_model * p_clamped + self.w_context * c_clamped)
        risk_score = round(max(0.0, min(100.0, raw_score)), 1)
        severity = ThresholdConfig.get_severity(risk_score)
        
        return RiskAssessment(
            input_type="URL",
            risk_score=risk_score,
            severity=severity,
            model_probability=round(p_clamped, 4),
            context_score=round(c_clamped, 4),
            weights={"model": round(self.w_model, 4), "context": round(self.w_context, 4)}
        )
        
    def calculate_file_risk(
        self,
        malware_probability: float,
        context_score: float = 0.0
    ) -> RiskAssessment:
        """
        Calculates unified risk score for Static PE malware threat analysis.
        Formula: 100 * [w_model * P(malware) + w_context * C(context)]
        """
        p_clamped = max(0.0, min(1.0, float(malware_probability)))
        c_clamped = max(0.0, min(1.0, float(context_score)))
        
        raw_score = 100.0 * (self.w_model * p_clamped + self.w_context * c_clamped)
        risk_score = round(max(0.0, min(100.0, raw_score)), 1)
        severity = ThresholdConfig.get_severity(risk_score)
        
        return RiskAssessment(
            input_type="FILE",
            risk_score=risk_score,
            severity=severity,
            model_probability=round(p_clamped, 4),
            context_score=round(c_clamped, 4),
            weights={"model": round(self.w_model, 4), "context": round(self.w_context, 4)}
        )

# Global default instance
risk_engine = RiskAnalysisEngine(
    weight_model=settings.WEIGHT_PHISHING,
    weight_context=settings.WEIGHT_PHISHING_CONTEXT
)
