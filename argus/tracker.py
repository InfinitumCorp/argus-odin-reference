from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Dict, Optional, Tuple
import uuid, math
from argus.models import Track, Classification, Provenance, new_fingerprint
from argus.detector import Detection
from argus.kalman import KalmanTrack

def haversine_m(lat1, lon1, lat2, lon2):
    R = 6371000
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp, dl = math.radians(lat2-lat1), math.radians(lon2-lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*R*math.atan2(math.sqrt(a), math.sqrt(1-a))

@dataclass
class TrackState:
    track_id: str
    classification: Classification
    confidence: float
    kalman: KalmanTrack
    alt_m: float
    sensors: List[str] = field(default_factory=list)
    first_seen: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    last_updated: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    hits: int = 1
    misses: int = 0
    is_threat: bool = False
    def to_track(self):
        lat, lon = self.kalman.position
        prov = Provenance(new_fingerprint("TRK"), list(set(self.sensors)), self.first_seen, self.last_updated)
        return Track(self.track_id, self.classification, min(0.99, self.confidence), lat, lon, self.alt_m, self.kalman.velocity_mps, self.kalman.heading_deg, prov, f"{self.classification.value} track across {len(set(self.sensors))} sensors", self.is_threat)

class MultiObjectTracker:
    def __init__(self, max_distance_m=150, max_misses=5, min_hits=2):
        self.tracks = {}
        self.max_distance_m = max_distance_m
        self.max_misses = max_misses
        self.min_hits = min_hits
    def update(self, detections: List[Detection]):
        now = datetime.now(timezone.utc)
        matched = set()
        for s in self.tracks.values():
            s.kalman.predict(max((now - s.last_updated).total_seconds(), 0.1))
        for det in detections:
            best, dist = self._match(det)
            if best and dist <= self.max_distance_m:
                self._update(self.tracks[best], det, now)
                matched.add(best)
            else:
                matched.add(self._create(det, now))
        for tid, s in list(self.tracks.items()):
            if tid not in matched: s.misses += 1
        for tid in [t for t, s in self.tracks.items() if s.misses > self.max_misses]:
            del self.tracks[tid]
        return [s.to_track() for s in self.tracks.values() if s.hits >= self.min_hits]
    def _match(self, det):
        best, best_d = None, float("inf")
        for tid, s in self.tracks.items():
            if det.classification != "unknown" and s.classification.value != det.classification and s.classification != Classification.UNKNOWN: continue
            lat, lon = s.kalman.position
            d = haversine_m(lat, lon, det.lat, det.lon)
            if d < best_d: best, best_d = tid, d
        return best, best_d
    def _update(self, s, det, now):
        s.kalman.update(det.lat, det.lon)
        s.sensors.append(det.sensor)
        s.hits += 1
        s.misses = 0
        s.last_updated = now
        s.confidence = max(s.confidence, det.confidence)
        if det.is_potential_threat or det.spectrum_anomaly: s.is_threat = True
    def _create(self, det, now):
        cmap = {"person": Classification.PERSON, "vehicle": Classification.VEHICLE, "uas": Classification.UAS}
        tid = f"TRK-{uuid.uuid4().hex[:8].upper()}"
        self.tracks[tid] = TrackState(tid, cmap.get(det.classification, Classification.UNKNOWN), det.confidence, KalmanTrack(det.lat, det.lon), det.alt_m, [det.sensor], now, now, 1, 0, det.is_potential_threat or det.spectrum_anomaly)
        return tid
