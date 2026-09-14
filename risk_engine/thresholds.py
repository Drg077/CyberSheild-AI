"""
Configurable Risk Severity Thresholds.
Defines prototype bands for Low, Medium, High, and Critical severity.
NOTE: These are prototype defaults and should be tuned based on deployment risk tolerance.
"""
from enum import Enum
from typing import Dict, Any

class SeverityLevel(str, Enum):
    LOW = "Low"
    MEDIUM = "Medium"
    HIGH = "High"
    CRITICAL = "Critical"

class ThresholdConfig:
    # Prototype default boundary values
    LOW_MIN: float = 0.0
    LOW_MAX: float = 29.0
    
    MEDIUM_MIN: float = 30.0
    MEDIUM_MAX: float = 59.0
    
    HIGH_MIN: float = 60.0
    HIGH_MAX: float = 79.0
    
    CRITICAL_MIN: float = 80.0
    CRITICAL_MAX: float = 100.0
    
    @classmethod
    def get_severity(cls, score: float) -> SeverityLevel:
        """
        Maps a 0-100 risk score to a SeverityLevel enum.
        Clamps values outside [0, 100] safely.
        """
        clamped = max(0.0, min(100.0, float(score)))
        if clamped <= cls.LOW_MAX:
            return SeverityLevel.LOW
        elif clamped <= cls.MEDIUM_MAX:
            return SeverityLevel.MEDIUM
        elif clamped <= cls.HIGH_MAX:
            return SeverityLevel.HIGH
        else:
            return SeverityLevel.CRITICAL
