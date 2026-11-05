from dataclasses import dataclass
from typing import List
from datetime import datetime, timezone

@dataclass
class SpectrumObservation:
    sensor: str
    timestamp: datetime
    lat: float
    lon: float
    interference_detected: bool
    jam_confidence: float

class SpectrumFusion:
    def __init__(self):
        self.observations = []
    def ingest(self, detections):
        self.observations.clear()
        now = datetime.now(timezone.utc)
        for d in detections:
            if d.get("spectrum_anomaly"):
                self.observations.append(SpectrumObservation(d["sensor"], now, d["lat"], d["lon"], True, d.get("confidence", 0.7)))
        return self.observations
    def summary(self):
        if not self.observations: return {"interference_events": 0, "status": "clear"}
        return {"interference_events": len(self.observations), "status": "interference_detected", "highest_confidence": max(o.jam_confidence for o in self.observations), "sensors": list({o.sensor for o in self.observations})}
