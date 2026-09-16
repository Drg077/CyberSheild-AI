"""
Pydantic Schemas for API Requests, Responses, and Audit Records.
"""
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional

class URLAnalysisRequest(BaseModel):
    url: str = Field(..., description="Target URL to be analyzed safely without navigation.", min_length=3, max_length=2048)

class MessageAnalysisRequest(BaseModel):
    text: str = Field(..., description="Message/email content to be analyzed for AI/human phishing indicators.", min_length=10, max_length=10000)

class DownloadAnalysisRequest(BaseModel):
    filename: str = Field(..., description="Name of the file being downloaded.", min_length=1, max_length=512)
    file_extension: str = Field(..., description="File extension (e.g. .exe, .pdf).", min_length=1, max_length=32)
    source_url: str = Field(..., description="Source page URL where download was initiated.", min_length=1, max_length=2048)
    download_url: str = Field(..., description="Direct download URL for the payload.", min_length=1, max_length=2048)

class SHAPFeatureItem(BaseModel):
    feature: str
    value: float
    shap_value: float
    absolute_impact: float
    direction: str

class HighlightedSpanItem(BaseModel):
    text: str
    start: int
    end: int
    weight: float

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
    download_source_url: Optional[str] = None
    download_url: Optional[str] = None
    highlighted_spans: Optional[List[Dict[str, Any]]] = None
    detector_probabilities: Optional[Dict[str, float]] = None

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
    download_source_url: Optional[str] = None
    download_url: Optional[str] = None

class HealthResponse(BaseModel):
    status: str
    service: str
    version: str
    phishing_model_loaded: bool
    malware_model_loaded: bool
    message_model_loaded: bool
    url_schema_version: str
    pe_schema_version: str
    message_schema_version: str
    timestamp: str
