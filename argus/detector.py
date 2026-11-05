from abc import ABC, abstractmethod
from typing import List, Dict, Any
from dataclasses import dataclass

@dataclass
class Detection:
    detection_id: str
    sensor: str
    lat: float
    lon: float
    alt_m: float
    velocity_mps: float
    heading_deg: float
    classification: str
    confidence: float
    spectrum_anomaly: bool = False
    is_potential_threat: bool = False
    raw: Dict[str, Any] = None

class Detector(ABC):
    @abstractmethod
    def detect(self, raw_observations: List[Dict[str, Any]]) -> List[Detection]: ...

class SimulatedDetector(Detector):
    def detect(self, raw_observations):
        return [Detection(
            detection_id=o.get("detection_id", "DET"),
            sensor=o["sensor"], lat=o["lat"], lon=o["lon"],
            alt_m=o.get("alt_m", 0), velocity_mps=o.get("velocity_mps", 0),
            heading_deg=o.get("heading_deg", 0), classification=o.get("raw_class", "unknown"),
            confidence=o.get("confidence", 0.5), spectrum_anomaly=o.get("spectrum_anomaly", False),
            is_potential_threat=o.get("is_potential_threat", False), raw=o
        ) for o in raw_observations]
