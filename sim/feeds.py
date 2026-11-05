import random
from datetime import datetime, timezone
from typing import List, Dict, Any

def generate_coherent_scenario(num_objects=5, observations_per_object=3) -> List[Dict[str, Any]]:
    base_lat, base_lon = 38.9072, -77.0369
    sensors = ["POLLEN-SWARM-01", "NEMESIS-FPV-03", "ORBIS-INDOOR-02", "DAEMON-WARDEN-01", "EON-WEARABLE-07", "HRVST-FIELD-04", "CAMERA-NORTH-GATE"]
    out, n = [], 0
    now = datetime.now(timezone.utc)
    for i in range(num_objects):
        tlat = base_lat + random.uniform(-0.015, 0.015)
        tlon = base_lon + random.uniform(-0.015, 0.015)
        cls = random.choice(["person", "vehicle", "uas", "uas", "unknown"])
        threat = cls == "uas" or random.random() < 0.2
        for s in random.sample(sensors, k=min(observations_per_object, len(sensors))):
            out.append({
                "detection_id": f"DET-{n:04d}", "sensor": s, "timestamp": now.isoformat(),
                "lat": tlat + random.uniform(-0.0003, 0.0003), "lon": tlon + random.uniform(-0.0003, 0.0003),
                "alt_m": random.uniform(10, 100) if cls == "uas" else random.uniform(0, 15),
                "velocity_mps": random.uniform(0, 15), "heading_deg": random.uniform(0, 360),
                "raw_class": cls, "confidence": random.uniform(0.65, 0.95),
                "spectrum_anomaly": threat and random.random() < 0.3, "is_potential_threat": threat,
            })
            n += 1
    random.shuffle(out)
    return out
