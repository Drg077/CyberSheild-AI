"""
Analysis History API routes.
"""
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.orm import Session
from database.db_session import get_db
from database.repository import ThreatAnalysisRepository
from backend.schemas.schemas import HistoryItemResponse, ThreatAnalysisResponse

router = APIRouter(prefix="/api/v1/history", tags=["History"])

@router.get("", response_model=List[HistoryItemResponse])
def get_history(
    limit: int = Query(50, ge=1, le=200),
    input_type: Optional[str] = Query(None, pattern="^(URL|FILE)$"),
    db: Session = Depends(get_db)
):
    repo = ThreatAnalysisRepository(db)
    records = repo.get_recent(limit=limit, input_type=input_type)
    return [
        HistoryItemResponse(
            id=r.id,
            timestamp=r.timestamp.isoformat(),
            input_type=r.input_type,
            target=r.target,
            prediction=r.prediction,
            probability=r.probability,
            risk_score=r.risk_score,
            severity=r.severity,
            decision=r.decision,
            title=r.title,
            summary=r.summary,
            model_version=r.model_version,
            file_sha256=r.file_sha256
        )
        for r in records
    ]

@router.get("/{record_id}", response_model=ThreatAnalysisResponse)
def get_record_detail(record_id: str, db: Session = Depends(get_db)):
    repo = ThreatAnalysisRepository(db)
    record = repo.get_by_id(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
        
    return ThreatAnalysisResponse(
        id=record.id,
        timestamp=record.timestamp.isoformat(),
        input_type=record.input_type,
        target=record.target,
        prediction=record.prediction,
        probability=record.probability,
        risk_score=record.risk_score,
        severity=record.severity,
        decision=record.decision,
        title=record.title,
        recommendation=record.recommendation,
        summary=record.summary,
        reasons=[],
        top_features=record.top_features or [],
        model_version=record.model_version,
        feature_schema_version=record.feature_schema_version,
        disclaimer="",
        file_sha256=record.file_sha256
    )

@router.delete("", response_model=dict)
def clear_history(db: Session = Depends(get_db)):
    repo = ThreatAnalysisRepository(db)
    deleted = repo.clear_history()
    return {"message": f"Successfully cleared {deleted} history records."}
