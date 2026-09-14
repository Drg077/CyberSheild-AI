"""
SQLAlchemy ORM models for Threat Analysis and Prediction History.
"""
import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, DateTime, Text, JSON
from database.db_session import Base

class ThreatAnalysisRecord(Base):
    __tablename__ = "threat_analyses"
    
    id = Column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    timestamp = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    input_type = Column(String(10), nullable=False, index=True) # 'URL' or 'FILE'
    target = Column(String(1024), nullable=False) # Sanitized URL or Filename
    file_sha256 = Column(String(64), nullable=True) # For file analyses
    
    # Prediction & Risk outputs
    prediction = Column(String(20), nullable=False) # 'Phishing', 'Legitimate', 'Malicious', 'Benign'
    probability = Column(Float, nullable=False) # 0.0 to 1.0
    risk_score = Column(Float, nullable=False) # 0.0 to 100.0
    severity = Column(String(20), nullable=False) # 'Low', 'Medium', 'High', 'Critical'
    decision = Column(String(20), nullable=False) # 'ALLOW', 'CAUTION', 'WARN', 'BLOCK', 'QUARANTINE'
    
    # Explanations & Action
    title = Column(String(128), nullable=False)
    recommendation = Column(Text, nullable=False)
    summary = Column(Text, nullable=False)
    top_features = Column(JSON, nullable=False) # List of SHAP attributions
    
    # Audit & Model metadata
    model_version = Column(String(20), nullable=False)
    feature_schema_version = Column(String(20), nullable=False)
