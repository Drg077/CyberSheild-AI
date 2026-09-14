"""
Repository layer for Threat Analysis History CRUD operations.
"""
from typing import List, Optional
from sqlalchemy.orm import Session
from database.models import ThreatAnalysisRecord

class ThreatAnalysisRepository:
    def __init__(self, db: Session):
        self.db = db
        
    def create(self, record_data: dict) -> ThreatAnalysisRecord:
        """Saves a new threat analysis record to SQLite."""
        record = ThreatAnalysisRecord(**record_data)
        self.db.add(record)
        self.db.commit()
        self.db.refresh(record)
        return record
        
    def get_by_id(self, record_id: str) -> Optional[ThreatAnalysisRecord]:
        """Fetches a specific analysis record by UUID."""
        return self.db.query(ThreatAnalysisRecord).filter(ThreatAnalysisRecord.id == record_id).first()
        
    def get_recent(self, limit: int = 50, input_type: Optional[str] = None) -> List[ThreatAnalysisRecord]:
        """Retrieves recent threat analyses, optionally filtered by input type."""
        query = self.db.query(ThreatAnalysisRecord)
        if input_type:
            query = query.filter(ThreatAnalysisRecord.input_type == input_type.upper())
        return query.order_by(ThreatAnalysisRecord.timestamp.desc()).limit(limit).all()
        
    def clear_history(self) -> int:
        """Purges history records (used in test fixtures/maintenance)."""
        count = self.db.query(ThreatAnalysisRecord).delete()
        self.db.commit()
        return count
