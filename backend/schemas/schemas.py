"""
Pydantic Schemas for API Requests, Responses, and Audit Records.
"""
from pydantic import BaseModel, Field, HttpUrl
from typing import List, Dict, Any, Optional
from datetime import datetime

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL to be analyzed safely without navigation.", min_length=3, max_length=2048)

class SHAPFeatureItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    absolute_impact: float
    direction: str

class ThreatAnalysisResponse(BaseModel):
    id: str
    timestamp: str
    input_type: str
    target: str
    prediction: str
    probability: float
    risk_score: float
    severity: str
    decision: str
    title: str
    recommendation: str
    summary: str
    reasons: List[str]
    top_features: List[Dict[str, Any]]
    model_version: str
    feature_schema_version: str
    disclaimer: str
    file_sha256: Optional[str] = None

class HistoryItemResponse(BaseModel):
    id: str
    timestamp: str
    input_type: str
    target: str
    prediction: str
    probability: float
    risk_score: float
    severity: str
    decision: str
    title: str
    summary: str
    model_version: str
    file_sha256: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    phishing_model_loaded: bool
    malware_model_loaded: bool
    url_schema_version: str
    pe_schema_version: str
    timestamp: str
