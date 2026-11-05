import csv, json
from pathlib import Path
from typing import List, Dict, Any
from datetime import datetime

def load_dataset(path: str) -> List[Dict[str, Any]]:
    p = Path(path)
    if p.suffix.lower() == ".csv":
        out = []
        with open(p, newline="", encoding="utf-8") as f:
            for i, row in enumerate(csv.DictReader(f)):
                out.append({
                    "detection_id": row.get("detection_id", f"CSV-{i}"),
                    "sensor": row.get("sensor", "UNK"),
                    "lat": float(row.get("lat", 0)), "lon": float(row.get("lon", 0)),
                    "alt_m": float(row.get("alt_m", 0)), "velocity_mps": float(row.get("velocity_mps", 0)),
                    "heading_deg": float(row.get("heading_deg", 0)),
                    "raw_class": row.get("raw_class", "unknown"),
                    "confidence": float(row.get("confidence", 0.7)),
                    "spectrum_anomaly": str(row.get("spectrum_anomaly","")).lower() in ("true","1","yes"),
                    "is_potential_threat": str(row.get("is_potential_threat","")).lower() in ("true","1","yes"),
                })
        return out
    if p.suffix.lower() == ".jsonl":
        return [json.loads(line) for line in open(p) if line.strip()]
    raise ValueError("Unsupported format")
