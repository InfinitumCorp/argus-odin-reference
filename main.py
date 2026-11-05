#!/usr/bin/env python3
"""
>_ARGUS™ Military Edition — Reference Build
"""
import json, sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent))

from argus.streaming import StreamingProcessor
from argus.dataset import load_dataset
from argus.edge_store import EdgeStore
from argus.firmament import FirmamentRecorder
from argus.query import SceneQuery
from argus.cop import generate_cop_html
from sim.feeds import generate_coherent_scenario

def split_into_batches(observations, batch_size=5):
    for i in range(0, len(observations), batch_size):
        yield observations[i:i + batch_size]

def run_pipeline(raw, source):
    print(f">_ARGUS™ Military Edition — {source}")
    print(f"Observations: {len(raw)}")
    processor = StreamingProcessor()
    pictures = list(processor.process_stream(split_into_batches(raw)))
    picture = pictures[-1] if pictures else {}
    print(f"Tracks: {picture.get('track_count', 0)}  Alerts: {picture.get('alert_count', 0)}")
    store = EdgeStore()
    store.save_picture(picture)
    FirmamentRecorder().record_batch(picture)
    store.simulate_mesh_sync()
    generate_cop_html(picture, "cop.html")
    print(SceneQuery().ask("What UAS are in the picture?", picture)["answer"])
    print("Recommendations remain advisory.")
    Path("argus_picture.json").write_text(json.dumps(picture, indent=2))

def main():
    if len(sys.argv) > 1:
        run_pipeline(load_dataset(sys.argv[1]), sys.argv[1])
    else:
        run_pipeline(generate_coherent_scenario(6, 4), "simulated")

if __name__ == "__main__":
    main()
