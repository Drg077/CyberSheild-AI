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
    input_type: Optional[str] = Query(None, pattern="^(URL|FILE|MESSAGE|DOWNLOAD)$"),
    db: Session = Depends(get_db)
):
    repo = ThreatAnalysisRepository(db)
    records = repo.get_recent(limit=limit, input_type=input_type)
    
    response_items = []
    for r in records:
        ctx_s = getattr(r, "context_score", None)
        if ctx_s is None and r.detector_probabilities:
            ctx_s = r.detector_probabilities.get("context_score", 0.0)
        
        pred_lower = r.prediction.lower()
        is_legit = pred_lower in ["legitimate", "benign", "legitimate / safe"]
        pred_like = round(1.0 - r.probability, 4) if is_legit else round(r.probability, 4)
        pred_label = "Legitimate Likelihood" if is_legit else ("Malware Likelihood" if "mal" in pred_lower else "Phishing Likelihood")

        response_items.append(
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
                file_sha256=r.file_sha256,
                download_source_url=r.download_source_url,
                download_url=r.download_url,
                context_score=round(float(ctx_s), 4) if ctx_s is not None else 0.0,
                prediction_likelihood=pred_like,
                prediction_likelihood_label=pred_label
            )
        )
    return response_items

@router.get("/{record_id}", response_model=ThreatAnalysisResponse)
def get_record_detail(record_id: str, db: Session = Depends(get_db)):
    repo = ThreatAnalysisRepository(db)
    record = repo.get_by_id(record_id)
    if not record:
        raise HTTPException(status_code=404, detail="Analysis record not found.")
        
    ctx_s = getattr(record, "context_score", None)
    if ctx_s is None and record.detector_probabilities:
        ctx_s = record.detector_probabilities.get("context_score", 0.0)

    pred_lower = record.prediction.lower()
    is_legit = pred_lower in ["legitimate", "benign", "legitimate / safe"]
    pred_like = round(1.0 - record.probability, 4) if is_legit else round(record.probability, 4)
    pred_label = "Legitimate Likelihood" if is_legit else ("Malware Likelihood" if "mal" in pred_lower else "Phishing Likelihood")

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
        file_sha256=record.file_sha256,
        download_source_url=record.download_source_url,
        download_url=record.download_url,
        highlighted_spans=record.highlighted_spans,
        detector_probabilities={k: float(v) for k, v in record.detector_probabilities.items() if isinstance(v, (int, float))} if record.detector_probabilities else None,
        context_score=round(float(ctx_s), 4) if ctx_s is not None else 0.0,
        prediction_likelihood=pred_like,
        prediction_likelihood_label=pred_label,
        threat_intel=record.detector_probabilities.get("threat_intel") if record.detector_probabilities and isinstance(record.detector_probabilities.get("threat_intel"), dict) else None,
        domain_reputation=record.detector_probabilities.get("domain_reputation") if record.detector_probabilities and isinstance(record.detector_probabilities.get("domain_reputation"), dict) else None,
        domain_verification=record.detector_probabilities.get("domain_verification") if record.detector_probabilities and isinstance(record.detector_probabilities.get("domain_verification"), dict) else None,
        final_assessment=record.detector_probabilities.get("final_assessment") if record.detector_probabilities and isinstance(record.detector_probabilities.get("final_assessment"), str) else None,
        risk_score_breakdown=record.detector_probabilities.get("risk_score_breakdown") if record.detector_probabilities and isinstance(record.detector_probabilities.get("risk_score_breakdown"), dict) else None
    )

@router.delete("", response_model=dict)
def clear_history(db: Session = Depends(get_db)):
    repo = ThreatAnalysisRepository(db)
    deleted = repo.clear_history()
    return {"message": f"Successfully cleared {deleted} history records."}
