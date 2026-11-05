from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Any
from enum import Enum
import uuid

class Classification(Enum):
    UNKNOWN = "unknown"
    PERSON = "person"
    VEHICLE = "vehicle"
    UAS = "uas"
    JAMMER = "jammer"
    ANOMALOUS = "anomalous"

class ThreatType(Enum):
    UAS = "uas"
    ANOMALOUS_TRACK = "anomalous_track"
    SPECTRUM_INTERFERENCE = "spectrum_interference"

@dataclass
class Provenance:
    fingerprint: str
    sensors: List[str]
    first_seen: datetime
    last_updated: datetime
    def to_dict(self):
        return {"fingerprint": self.fingerprint, "sensors": self.sensors, "first_seen": self.first_seen.isoformat(), "last_updated": self.last_updated.isoformat()}

@dataclass
class Track:
    track_id: str
    classification: Classification
    confidence: float
    lat: float
    lon: float
    alt_m: float
    velocity_mps: float
    heading_deg: float
    provenance: Provenance
    explanation: str = ""
    is_threat: bool = False
    def to_dict(self):
        return {"track_id": self.track_id, "classification": self.classification.value, "confidence": round(self.confidence, 3), "position": {"lat": self.lat, "lon": self.lon, "alt_m": self.alt_m}, "velocity_mps": self.velocity_mps, "heading_deg": self.heading_deg, "is_threat": self.is_threat, "explanation": self.explanation, "provenance": self.provenance.to_dict()}

@dataclass
class DefenseAlert:
    alert_id: str
    threat_type: ThreatType
    priority: float
    confidence: float
    linked_tracks: List[str]
    explanation: str
    recommendation: str
    provenance: Provenance
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    def to_dict(self):
        return {"alert_id": self.alert_id, "threat_type": self.threat_type.value, "priority": round(self.priority, 3), "confidence": round(self.confidence, 3), "linked_tracks": self.linked_tracks, "explanation": self.explanation, "recommendation": self.recommendation, "created_at": self.created_at.isoformat(), "provenance": self.provenance.to_dict()}

def new_fingerprint(prefix="ARGUS"):
    return f"{prefix}-{uuid.uuid4().hex[:16].upper()}"
