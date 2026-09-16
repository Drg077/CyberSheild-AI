"""
Message Content Threat Prediction API route.
Analyzes email / SMS / communication text for GenAI and human phishing patterns.
"""
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session
from database.db_session import get_db
from backend.schemas.schemas import MessageAnalysisRequest, ThreatAnalysisResponse
from backend.services.threat_service import ThreatService

router = APIRouter(prefix="/api/v1/analyze", tags=["Message Analysis"])

@router.post("/message", response_model=ThreatAnalysisResponse)
def analyze_message(request: MessageAnalysisRequest, db: Session = Depends(get_db)):
    clean_text = request.text.strip()
    if not clean_text:
        raise HTTPException(status_code=422, detail="Message text cannot be empty.")
    if len(clean_text) < 10:
        raise HTTPException(status_code=422, detail="Message text must be at least 10 characters long.")
    if len(clean_text) > 10000:
        raise HTTPException(status_code=422, detail="Message text exceeds maximum permitted limit of 10000 characters.")
        
    try:
        response = ThreatService.analyze_message(text=clean_text, db=db)
        return response
    except Exception as e:
        # Prevent leaking internal stack traces
        raise HTTPException(status_code=500, detail="Failed to complete message security analysis.")
