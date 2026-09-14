"""
Health & Service Status API route.
"""
from datetime import datetime, timezone
from fastapi import APIRouter
from backend.config import settings
from backend.schemas.schemas import HealthResponse
from feature_extraction.feature_contract import URLFeatureContract, PEFeatureContract

router = APIRouter(prefix="/api/v1", tags=["Health"])

@router.get("/health", response_model=HealthResponse)
def health_check():
    phish_exists = (settings.MODELS_DIR / "phishing" / "model" / "phishing_model.joblib").exists()
    mal_exists = (settings.MODELS_DIR / "malware" / "model" / "malware_model.joblib").exists()
    
    return HealthResponse(
        status="healthy",
        service=settings.PROJECT_NAME,
        version=settings.VERSION,
        phishing_model_loaded=phish_exists,
        malware_model_loaded=mal_exists,
        url_schema_version=URLFeatureContract.SCHEMA_VERSION,
        pe_schema_version=PEFeatureContract.SCHEMA_VERSION,
        timestamp=datetime.now(timezone.utc).isoformat()
    )
