from datetime import datetime, timezone
from typing import List, Dict, Any

class FirmamentRecorder:
    def __init__(self):
        self.records = []
    def record_track(self, t):
        rec = {"type": "track", "fingerprint": t["provenance"]["fingerprint"], "track_id": t["track_id"], "ledger": "private_firmament"}
        self.records.append(rec)
        return rec["fingerprint"]
    def record_alert(self, a):
        rec = {"type": "defense_alert", "fingerprint": a["provenance"]["fingerprint"], "alert_id": a["alert_id"], "ledger": "private_firmament"}
        self.records.append(rec)
        return rec["fingerprint"]
    def record_batch(self, picture):
        fps = []
        for t in picture.get("tracks", []): fps.append(self.record_track(t))
        for a in picture.get("defense_alerts", []): fps.append(self.record_alert(a))
        return fps
    def export(self):
        return list(self.records)
