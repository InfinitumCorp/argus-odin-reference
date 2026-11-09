#!/usr/bin/env python3
"""
>_ARGUS™ Military Edition — Reference Build
"""
import argparse
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from argus.streaming import StreamingProcessor
from argus.dataset import load_dataset
from argus.edge_store import EdgeStore
from argus.firmament import FirmamentRecorder
from argus.query import SceneQuery
from argus.cop import generate_cop_html
from argus.geo import GeoAnnotator, GeoDataError, load_locked_dataset
from argus.settings import load_settings, resolve_geo_enabled, save_settings
from sim.feeds import generate_coherent_scenario


def split_into_batches(observations, batch_size=5):
    for i in range(0, len(observations), batch_size):
        yield observations[i:i + batch_size]


def run_pipeline(raw, source, geo=None):
    print(f">_ARGUS™ Military Edition — {source}")
    print(f"Observations: {len(raw)}")
    processor = StreamingProcessor(geo=geo)
    pictures = list(processor.process_stream(split_into_batches(raw)))
    picture = pictures[-1] if pictures else {}
    print(f"Tracks: {picture.get('track_count', 0)}  Alerts: {picture.get('alert_count', 0)}")
    if geo is not None:
        count = len((picture.get("geo") or {}).get("entries", []))
        print(f"Geo-routing annotations: {count}")
    store = EdgeStore()
    store.save_picture(picture)
    recorder = FirmamentRecorder()
    recorder.record_batch(picture)
    if geo is not None and picture.get("geo"):
        recorder.record_geo(picture["geo"])
        store.save_provenance(recorder.export())
    store.simulate_mesh_sync()
    generate_cop_html(picture, "cop.html")
    print(SceneQuery().ask("What UAS are in the picture?", picture)["answer"])
    print("Recommendations remain advisory.")
    Path("argus_picture.json").write_text(json.dumps(picture, indent=2))
    return picture


def parse_args(argv):
    parser = argparse.ArgumentParser(prog="main.py")
    parser.add_argument("dataset", nargs="?", help="CSV or JSONL observations")
    parser.add_argument(
        "--geo-routing",
        choices=("on", "off"),
        help="Persist the cyber geo-routing toggle (default off)",
    )
    return parser.parse_args(argv)


def main(argv=None, settings_path=None, geo_loader=None):
    args = parse_args(sys.argv[1:] if argv is None else argv)
    if settings_path is None:
        settings_path = Path(os.environ.get("ARGUS_SETTINGS", "argus_settings.json"))
    else:
        settings_path = Path(settings_path)
    if geo_loader is None:
        geo_loader = load_locked_dataset
    try:
        settings = load_settings(settings_path)
        cli = None
        if args.geo_routing is not None:
            cli = args.geo_routing == "on"
            settings["geo_routing"] = cli
            save_settings(settings_path, settings)
            print(f"Geo-routing: {'on' if cli else 'off'}")
        enabled = resolve_geo_enabled(os.environ, settings, cli)
    except ValueError as exc:
        print(str(exc), file=sys.stderr)
        return 2
    geo = None
    if enabled:
        if cli is None:
            print("Geo-routing: on")
        try:
            geo = GeoAnnotator(geo_loader())
        except (GeoDataError, OSError) as exc:
            print(f"Geo-routing unavailable: {exc}", file=sys.stderr)
            return 1
    if args.dataset:
        run_pipeline(load_dataset(args.dataset), args.dataset, geo=geo)
    else:
        run_pipeline(generate_coherent_scenario(6, 4), "simulated", geo=geo)
    return 0


if __name__ == "__main__":
    sys.exit(main())
