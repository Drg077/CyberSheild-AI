"""
Download Threat Analysis API Endpoint.
Processes file download metadata (filename, extension, source URL, download URL)
through the ThreatService orchestration pipeline without receiving binary contents.
"""
from fastapi import APIRouter, Depends, status
from sqlalchemy.orm import Session

from backend.schemas.schemas import DownloadAnalysisRequest, ThreatAnalysisResponse
from backend.services.threat_service import ThreatService
from database.db_session import get_db

router = APIRouter(prefix="/api/v1", tags=["Download Analysis"])

@router.post(
    "/analyze/download",
    response_model=ThreatAnalysisResponse,
    status_code=status.HTTP_200_OK,
    summary="Analyze file download metadata for cyber threats",
    description="Evaluates file download risk from filename, extension, source URL, and direct download URL."
)
def analyze_download(
    request: DownloadAnalysisRequest,
    db: Session = Depends(get_db)
) -> ThreatAnalysisResponse:
    """
    Analyzes download metadata against trained URL and contextual risk classifiers.
    CRITICAL: Never accepts or processes raw file binary content.
    """
    return ThreatService.analyze_download(
        filename=request.filename,
        file_extension=request.file_extension,
        source_url=request.source_url,
        download_url=request.download_url,
        db=db
    )
