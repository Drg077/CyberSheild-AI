"""
Static PE File Malware Analysis API route.
"""
from fastapi import APIRouter, Depends, UploadFile, File, HTTPException
from sqlalchemy.orm import Session
from database.db_session import get_db
from backend.schemas.schemas import ThreatAnalysisResponse
from backend.services.file_handler import process_untrusted_file
from backend.services.threat_service import ThreatService

router = APIRouter(prefix="/api/v1/analyze", tags=["File Analysis"])

@router.post("/file", response_model=ThreatAnalysisResponse)
async def analyze_file(
    file: UploadFile = File(...),
    db: Session = Depends(get_db)
):
    # Process untrusted file safely
    features_df, filename, sha256 = await process_untrusted_file(file)
    
    try:
        response = ThreatService.analyze_file(
            features_df=features_df,
            filename=filename,
            sha256=sha256,
            db=db
        )
        return response
    except Exception as e:
        raise HTTPException(status_code=500, detail="Failed to complete file security analysis.")
