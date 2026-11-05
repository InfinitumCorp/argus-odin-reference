from datetime import datetime, timezone
from typing import List, Dict, Any
from argus.models import DefenseAlert, ThreatType, Provenance, new_fingerprint
from argus.tracker import MultiObjectTracker
from argus.spectrum import SpectrumFusion
from argus.anticipation import AnticipationEngine
from argus.detector import Detector, SimulatedDetector

class ArgusFusionEngine:
    def __init__(self, detector=None):
        self.detector = detector or SimulatedDetector()
        self.tracker = MultiObjectTracker()
        self.spectrum = SpectrumFusion()
        self.anticipation = AnticipationEngine()
        self.alerts = []
    def ingest_and_fuse(self, raw):
        self.alerts.clear()
        dets = self.detector.detect(raw)
        self.spectrum.ingest(raw)
        spec = self.spectrum.summary()
        tracks = self.tracker.update(dets)
        for t in tracks:
            if t.is_threat or t.classification.value == "uas":
                a = self._alert(t)
                if a: self.alerts.append(a)
        if spec.get("interference_events", 0):
            self.alerts.append(self._spec_alert(spec))
        self.alerts.sort(key=lambda a: a.priority, reverse=True)
        pic = {"timestamp": datetime.now(timezone.utc).isoformat(), "track_count": len(tracks), "alert_count": len(self.alerts), "tracks": [t.to_dict() for t in tracks], "defense_alerts": [a.to_dict() for a in self.alerts], "spectrum": spec}
        pic["forecasts"] = self.anticipation.forecast(pic)
        return pic
    def _alert(self, t):
        ttype = ThreatType.UAS if t.classification.value == "uas" else ThreatType.ANOMALOUS_TRACK
        rec = "Advisory only. Human approval required."
        now = datetime.now(timezone.utc)
        prov = Provenance(new_fingerprint("ALT"), t.provenance.sensors, now, now)
        return DefenseAlert(f"ALT-{t.track_id}", ttype, min(1.0, t.confidence*1.1), t.confidence, [t.track_id], t.explanation, rec, prov)
    def _spec_alert(self, spec):
        now = datetime.now(timezone.utc)
        prov = Provenance(new_fingerprint("SPC"), spec.get("sensors", []), now, now)
        return DefenseAlert("ALT-SPECTRUM", ThreatType.SPECTRUM_INTERFERENCE, 0.8, 0.8, [], "Spectrum interference detected.", "Advisory only.", prov)
