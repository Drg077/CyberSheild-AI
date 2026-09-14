"""
URL Threat Prediction API route.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db_session import get_db
from backend.schemas.schemas import URLAnalysisRequest, ThreatAnalysisResponse
from backend.services.threat_service import ThreatService

router = APIRouter(prefix="/api/v1/analyze", tags=["URL Analysis"])

@router.post("/url", response_model=ThreatAnalysisResponse)
def analyze_url(request: URLAnalysisRequest, db: Session = Depends(get_db)):
    clean_url = request.url.strip()
    if not clean_url:
        raise HTTPException(status_code=422, detail="URL cannot be empty.")
    if len(clean_url) > 2048:
        raise HTTPException(status_code=422, detail="URL length exceeds maximum permitted limit.")
        
    try:
        response = ThreatService.analyze_url(url=clean_url, db=db)
        return response
    except Exception as e:
        # Prevent leaking internal stack traces
        raise HTTPException(status_code=500, detail="Failed to complete URL security analysis.")
