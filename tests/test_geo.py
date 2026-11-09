"""Synthetic v2fly geo fixtures, settings, and the default-off pipeline hook."""

import hashlib
import io
import ipaddress
import json
import os
import subprocess
import tempfile
import unittest
from contextlib import contextmanager, redirect_stderr, redirect_stdout
from pathlib import Path

import main as argus_main
from argus.cop import generate_cop_html
from argus.dataset import load_dataset
from argus.firmament import FirmamentRecorder
from argus.fusion import ArgusFusionEngine
from argus.geo import (
    ChecksumMismatch,
    GeoAnnotator,
    GeoDataError,
    GeoDataset,
    iter_fields,
    load_locked_dataset,
    load_lockfile,
    parse_sha256sum,
)
from argus.query import SceneQuery
from argus.settings import load_settings, resolve_geo_enabled, save_settings
from argus.streaming import StreamingProcessor
from scripts.fetch_geo_dat import _check_download_url, sync_datasets

ROOT = Path(__file__).resolve().parents[1]


def varint(number):
    out = bytearray()
    while True:
        piece = number & 0x7F
        number >>= 7
        if number:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def delimited(field, payload):
    return varint((field << 3) | 2) + varint(len(payload)) + payload


def vint_field(field, number):
    return varint((field << 3) | 0) + varint(number)


def text_field(field, text):
    return delimited(field, text.encode("utf-8"))


def cidr_message(ip, prefix):
    return delimited(1, ip) + vint_field(2, prefix)


def geoip_message(code, cidrs, inverse=False):
    body = text_field(1, code)
    for ip, prefix in cidrs:
        body += delimited(2, cidr_message(ip, prefix))
    if inverse:
        body += vint_field(3, 1)
    body += delimited(4, b"\xab")
    return body


def geoip_list(entries):
    return b"".join(delimited(1, entry) for entry in entries)


def domain_message(value, kind=0):
    body = b""
    if kind:
        body += vint_field(1, kind)
    body += text_field(2, value)
    body += delimited(3, text_field(1, "attr") + vint_field(2, 1))
    body += vint_field(4, 7)
    return body


def geosite_message(code, domains):
    body = text_field(1, code)
    for domain in domains:
        body += delimited(2, domain)
    return body


def geosite_list(entries):
    return b"".join(delimited(1, entry) for entry in entries)


def packed(address):
    return ipaddress.ip_address(address).packed


def sample_dataset():
    geoip = geoip_list([
        geoip_message("zz", [(packed("10.0.0.0"), 8)]),
        geoip_message("us", [(packed("10.1.2.0"), 24), (packed("10.1.2.9"), 32)]),
        geoip_message("cn", [(packed("10.1.2.9"), 32)]),
        geoip_message("nope", [(packed("0.0.0.0"), 0)], inverse=True),
        geoip_message("ts", [(ipaddress.ip_network("2001:db8::/32").network_address.packed, 32)]),
        geoip_message("mp", [(ipaddress.IPv6Address("::ffff:192.0.2.10").packed, 128)]),
        geoip_message("tx", [], inverse=False),
    ])
    # A text-form CIDR uses field 68000 instead of raw address bytes.
    text_cidr = vint_field(2, 32) + delimited(68000, b"198.51.100.7")
    text_entry = text_field(1, "lab") + delimited(2, text_cidr)
    geoip += delimited(1, text_entry)
    geosite = geosite_list([
        geosite_message("exact", [domain_message("www.example.com", 3)]),
        geosite_message("zone", [domain_message("example.com", 2)]),
        geosite_message("kw", [domain_message("ads", 0)]),
        geosite_message("svc", [domain_message(r"^svc-.+\.example\.com$", 1)]),
        geosite_message("skip", [domain_message("   ", 0)]),
    ])
    return GeoDataset.from_bytes(geoip, geosite)


def observation(detection_id, **extra):
    item = {
        "detection_id": detection_id,
        "sensor": "SENSOR-1",
        "lat": 38.9,
        "lon": -77.0,
        "alt_m": 1,
        "velocity_mps": 0,
        "heading_deg": 0,
        "raw_class": "person",
        "confidence": 0.9,
        "spectrum_anomaly": False,
        "is_potential_threat": False,
    }
    item.update(extra)
    return item


@contextmanager
def isolated_env():
    saved = os.environ.copy()
    try:
        os.environ.pop("INFINITUM_GEO_ENABLED", None)
        os.environ.pop("ARGUS_SETTINGS", None)
        yield
    finally:
        os.environ.clear()
        os.environ.update(saved)


@contextmanager
def temp_cwd():
    original = os.getcwd()
    with tempfile.TemporaryDirectory() as tmp:
        os.chdir(tmp)
        try:
            yield Path(tmp)
        finally:
            os.chdir(original)


class GeoDatTests(unittest.TestCase):
    def test_longest_prefix_first_match_and_inverse_skipped(self):
        dataset = sample_dataset()
        self.assertEqual(dataset.country_for_ip("10.1.2.9"), "us")
        self.assertEqual(dataset.country_for_ip("10.1.2.8"), "us")
        self.assertEqual(dataset.country_for_ip("10.9.9.9"), "zz")
        self.assertIsNone(dataset.country_for_ip("11.0.0.1"))
        self.assertIsNone(dataset.country_for_ip("not-an-ip"))
        self.assertEqual(dataset.country_for_ip("2001:db8:1::5"), "ts")
        self.assertIsNone(dataset.country_for_ip("2001:db9::1"))
        self.assertEqual(dataset.country_for_ip("192.0.2.10"), "mp")
        self.assertEqual(dataset.country_for_ip("::ffff:192.0.2.10"), "mp")
        self.assertEqual(dataset.country_for_ip("198.51.100.7"), "lab")

    def test_domain_rules_and_order(self):
        dataset = sample_dataset()
        self.assertEqual(dataset.categories_for_domain("www.example.com"), ["exact", "zone"])
        self.assertEqual(dataset.categories_for_domain("WWW.Example.COM."), ["exact", "zone"])
        self.assertEqual(dataset.categories_for_domain("https://www.example.com/a"), ["exact", "zone"])
        self.assertEqual(dataset.categories_for_domain("www.example.com:443"), ["exact", "zone"])
        self.assertEqual(dataset.categories_for_domain("example.com"), ["zone"])
        self.assertEqual(dataset.categories_for_domain("notexample.com"), [])
        self.assertEqual(dataset.categories_for_domain("myads.example.com"), ["zone", "kw"])
        self.assertEqual(dataset.categories_for_domain("svc-edge.example.com"), ["zone", "svc"])
        self.assertEqual(dataset.categories_for_domain("8.8.8.8"), [])
        self.assertEqual(dataset.categories_for_domain("a" * 300 + ".example.com"), [])

    def test_files_roundtrip_and_truncated_input(self):
        dataset = sample_dataset()
        with tempfile.TemporaryDirectory() as tmp:
            geoip = Path(tmp) / "geoip.dat"
            geosite = Path(tmp) / "geosite.dat"
            built = sample_dataset()
            geoip.write_bytes(_bytes_of(built))
            geosite.write_bytes(_geosite_bytes())
            loaded = GeoDataset.from_files(geoip, geosite)
        self.assertEqual(loaded.country_for_ip("10.9.9.9"), dataset.country_for_ip("10.9.9.9"))
        self.assertEqual(loaded.categories_for_domain("example.com"), ["zone"])
        with self.assertRaises(GeoDataError):
            list(iter_fields(b"\x0a\x10"))
        with self.assertRaises(GeoDataError):
            list(iter_fields(b"\x0f\x00"))

    def test_annotator_copies_entries_across_batches(self):
        annotator = GeoAnnotator(sample_dataset())
        processor = StreamingProcessor(geo=annotator)
        first = [observation("A", source_ip="10.1.2.9", domain="www.example.com")]
        second = [observation("B", host="svc-edge.example.com", ip="10.9.1.1")]
        pictures = processor.process_stream([first, second])
        self.assertEqual(len(pictures[0]["geo"]["entries"]), 1)
        self.assertEqual(pictures[0]["geo"]["policy"], "advisory-annotate")
        self.assertEqual(pictures[0]["geo"]["entries"][0]["country"], "us")
        self.assertEqual(pictures[0]["geo"]["entries"][0]["categories"], ["exact", "zone"])
        self.assertEqual(len(pictures[1]["geo"]["entries"]), 2)
        self.assertEqual(len(pictures[0]["geo"]["entries"]), 1)
        self.assertEqual(pictures[1]["geo"]["entries"][1]["country"], "zz")
        self.assertIn("svc", pictures[1]["geo"]["entries"][1]["categories"])
        self.assertNotIn("geo", ArgusFusionEngine().ingest_and_fuse(first))

    def test_off_picture_matches_default_shape(self):
        rows = [observation("A"), observation("B", sensor="SENSOR-2")]
        off = ArgusFusionEngine().ingest_and_fuse(rows)
        on = ArgusFusionEngine(geo=GeoAnnotator(sample_dataset())).ingest_and_fuse(rows)
        self.assertEqual(set(off), {"timestamp", "track_count", "alert_count", "tracks", "defense_alerts", "spectrum", "forecasts"})
        self.assertNotIn("geo", off)
        self.assertIn("geo", on)
        self.assertEqual(on["geo"]["entries"], [])
        self.assertEqual(off["track_count"], on["track_count"])
        self.assertEqual(off["alert_count"], on["alert_count"])
        self.assertEqual(
            [track["classification"] for track in off["tracks"]],
            [track["classification"] for track in on["tracks"]],
        )
        generic = SceneQuery().ask("status", off)["answer"]
        self.assertEqual(SceneQuery().ask("Which country is the source?", off)["answer"], generic)
        self.assertEqual(SceneQuery().ask("What UAS are in the picture?", off)["answer"], SceneQuery().ask("What UAS are in the picture?", on)["answer"])
        answered = SceneQuery().ask("Which country and domain category?", on)
        self.assertIn("Geo-routing is on", answered["answer"])

    def test_query_uses_annotations_only_when_present(self):
        rows = [observation("A", source_ip="10.1.2.9", domain="www.example.com"), observation("B", sensor="SENSOR-2")]
        picture = ArgusFusionEngine(geo=GeoAnnotator(sample_dataset())).ingest_and_fuse(rows)
        answer = SceneQuery().ask("What country is that domain?", picture)["answer"]
        self.assertIn("10.1.2.9 us", answer)
        self.assertIn("www.example.com exact, zone", answer)
        self.assertTrue(answer.startswith("Geo-routing:"))

    def test_firmament_logs_geo_only_when_asked(self):
        recorder = FirmamentRecorder()
        picture = {"tracks": [], "defense_alerts": [], "geo": {"policy": "advisory-annotate", "entries": [{"source_ip": "10.0.0.1"}]}}
        recorder.record_batch(picture)
        self.assertEqual(recorder.export(), [])
        fingerprint = recorder.record_geo(picture["geo"])
        saved = recorder.export()
        self.assertEqual(len(saved), 1)
        self.assertEqual(saved[0]["type"], "geo_annotation")
        self.assertEqual(saved[0]["fingerprint"], fingerprint)
        self.assertEqual(saved[0]["count"], 1)

    def test_sample_csv_shape_is_unchanged(self):
        rows = load_dataset(ROOT / "datasets" / "sample_observations.csv")
        self.assertEqual(len(rows), 4)
        self.assertEqual(set(rows[0]), {
            "detection_id", "sensor", "lat", "lon", "alt_m", "velocity_mps", "heading_deg",
            "raw_class", "confidence", "spectrum_anomaly", "is_potential_threat",
        })
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "extra.csv"
            path.write_text(
                "detection_id,sensor,lat,lon,alt_m,velocity_mps,heading_deg,raw_class,confidence,spectrum_anomaly,is_potential_threat,source_ip,domain\n"
                "X,S,1,2,3,4,5,person,0.5,false,false,10.1.2.9,www.example.com\n",
                encoding="utf-8",
            )
            loaded = load_dataset(path)
            self.assertEqual(loaded[0]["source_ip"], "10.1.2.9")
            self.assertEqual(loaded[0]["domain"], "www.example.com")
            jsonl = Path(tmp) / "extra.jsonl"
            jsonl.write_text(json.dumps({"detection_id": "J", "host": "example.com"}) + "\n", encoding="utf-8")
            self.assertEqual(load_dataset(jsonl)[0]["host"], "example.com")

    def test_pipeline_off_does_not_write_geo_provenance(self):
        rows = [observation("A", source_ip="10.1.2.9", domain="www.example.com"), observation("B", sensor="SENSOR-2")]
        with temp_cwd() as tmp:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                picture = argus_main.run_pipeline(rows, "fixture", geo=None)
            text = stdout.getvalue()
            self.assertNotIn("Geo-routing", text)
            self.assertIn("Recommendations remain advisory.", text)
            self.assertNotIn("geo", picture)
            self.assertEqual(list(Path(tmp, "edge_store").glob("provenance_*.json")), [])
            html = Path(tmp, "cop.html").read_text(encoding="utf-8")
            self.assertNotIn("Geo-routing", html)
            saved = json.loads(Path(tmp, "argus_picture.json").read_text(encoding="utf-8"))
            self.assertNotIn("geo", saved)

    def test_pipeline_on_annotates_without_changing_cop_layout(self):
        rows = []
        for index in range(6):
            rows.append(observation(
                f"D{index}",
                sensor=f"SENSOR-{index}",
                lat=38.9 + index * 0.01,
                source_ip=f"10.1.2.{index + 1}",
                domain="www.example.com",
            ))
        annotator = GeoAnnotator(sample_dataset())
        with temp_cwd() as tmp:
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                picture = argus_main.run_pipeline(rows, "fixture", geo=annotator)
            self.assertIn("Geo-routing annotations: 6", stdout.getvalue())
            self.assertEqual(len(picture["geo"]["entries"]), 6)
            self.assertTrue(all(entry["country"] == "us" for entry in picture["geo"]["entries"]))
            provenance = list(Path(tmp, "edge_store").glob("provenance_*.json"))
            self.assertEqual(len(provenance), 1)
            ledger = json.loads(provenance[0].read_text(encoding="utf-8"))
            self.assertIn("geo_annotation", {record["type"] for record in ledger["records"]})
            html = Path(tmp, "cop.html").read_text(encoding="utf-8")
            self.assertNotIn("geo", html.lower())
            self.assertIn("Common Operating Picture", html)

    def test_cop_helper_ignores_geo_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "cop.html"
            generate_cop_html({"tracks": [], "defense_alerts": [], "geo": {"enabled": True, "entries": []}}, target)
            self.assertNotIn("Geo-routing", target.read_text(encoding="utf-8"))


class SettingsTests(unittest.TestCase):
    def test_missing_file_defaults_off_and_false_string_stays_off(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "settings.json"
            self.assertEqual(load_settings(path), {"geo_routing": False})
            self.assertFalse(path.exists())
            path.write_text('{"geo_routing": "false"}\n', encoding="utf-8")
            self.assertFalse(load_settings(path)["geo_routing"])
            path.write_text('{"geo_routing": "on"}\n', encoding="utf-8")
            self.assertTrue(load_settings(path)["geo_routing"])
            save_settings(path, {"geo_routing": False})
            self.assertFalse(json.loads(path.read_text(encoding="utf-8"))["geo_routing"])

    def test_precedence_is_cli_then_env_then_file(self):
        settings = {"geo_routing": True}
        self.assertFalse(resolve_geo_enabled({}, settings, cli=False))
        self.assertTrue(resolve_geo_enabled({"INFINITUM_GEO_ENABLED": "0"}, settings, cli=True))
        self.assertFalse(resolve_geo_enabled({"INFINITUM_GEO_ENABLED": "off"}, settings))
        self.assertTrue(resolve_geo_enabled({"INFINITUM_GEO_ENABLED": "yes"}, {"geo_routing": False}))
        self.assertFalse(resolve_geo_enabled({}, {"geo_routing": False}))
        self.assertTrue(resolve_geo_enabled({"INFINITUM_GEO_ENABLED": ""}, settings))
        with self.assertRaises(ValueError):
            resolve_geo_enabled({"INFINITUM_GEO_ENABLED": "maybe"}, settings)

    def test_cli_persists_toggle_and_default_run_skips_loader(self):
        calls = []

        def loader():
            calls.append("load")
            return sample_dataset()

        with isolated_env(), temp_cwd():
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = argus_main.main([], settings_path="argus_settings.json", geo_loader=loader)
            self.assertEqual(code, 0)
            self.assertEqual(calls, [])
            self.assertNotIn("Geo-routing", stdout.getvalue())
            self.assertFalse(Path("argus_settings.json").exists())
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = argus_main.main(["--geo-routing", "on"], settings_path="argus_settings.json", geo_loader=loader)
            self.assertEqual(code, 0)
            self.assertEqual(calls, ["load"])
            self.assertTrue(json.loads(Path("argus_settings.json").read_text(encoding="utf-8"))["geo_routing"])
            self.assertIn("Geo-routing: on", stdout.getvalue())
            os.environ["INFINITUM_GEO_ENABLED"] = "off"
            stdout = io.StringIO()
            with redirect_stdout(stdout):
                code = argus_main.main([], settings_path="argus_settings.json", geo_loader=loader)
            self.assertEqual(code, 0)
            self.assertEqual(calls, ["load"])
            self.assertNotIn("Geo-routing: on", stdout.getvalue())

    def test_enabled_without_data_returns_error(self):
        def loader():
            raise GeoDataError("missing data/geo/geoip.dat")

        with isolated_env(), temp_cwd():
            stderr = io.StringIO()
            with redirect_stdout(io.StringIO()), redirect_stderr(stderr):
                code = argus_main.main(["--geo-routing", "on"], settings_path="argus_settings.json", geo_loader=loader)
            self.assertEqual(code, 1)
            self.assertIn("Geo-routing unavailable", stderr.getvalue())
            self.assertFalse(Path("cop.html").exists())


class LockAndFetchTests(unittest.TestCase):
    def test_lockfile_pins_v2fly_releases(self):
        lock = load_lockfile(ROOT / "geo-datasets.lock.json")
        by_id = {entry["id"]: entry for entry in lock["datasets"]}
        self.assertEqual(by_id["geoip"]["tag"], "202611080027")
        self.assertEqual(by_id["geoip"]["filename"], "geoip.dat")
        self.assertEqual(by_id["geoip"]["sha256"], "eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2")
        self.assertEqual(
            by_id["geoip"]["url"],
            "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat",
        )
        self.assertEqual(by_id["geosite"]["tag"], "20261108011013")
        self.assertEqual(by_id["geosite"]["asset"], "dlc.dat")
        self.assertEqual(by_id["geosite"]["filename"], "geosite.dat")
        self.assertEqual(by_id["geosite"]["sha256"], "dc4192dd1b644a38276ed06136d26e729fa674d25785adb38c87e040e92376b2")
        self.assertEqual(by_id["geosite"]["license"], "MIT")
        self.assertEqual(by_id["geoip"]["license"], "CC-BY-SA-4.0")

    def test_sha256sum_parser_and_forbidden_upstream(self):
        pinned = "eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2"
        dlc = "dc4192dd1b644a38276ed06136d26e729fa674d25785adb38c87e040e92376b2"
        self.assertEqual(parse_sha256sum(f"{pinned}  geoip.dat\n", "geoip.dat"), pinned)
        self.assertEqual(parse_sha256sum(f"{dlc}  dlc.dat\n", "dlc.dat"), dlc)
        with self.assertRaises(GeoDataError):
            parse_sha256sum(f"{pinned}  other.dat\n", "geoip.dat")
        raw = json.loads((ROOT / "geo-datasets.lock.json").read_text(encoding="utf-8"))
        raw["datasets"][0]["project"] = "https://github.com/SagerNet/sing-box"
        with self.assertRaises(GeoDataError):
            from argus.geo import validate_lockfile
            validate_lockfile(raw)

    def test_sync_stops_on_official_mismatch_and_installs_on_match(self):
        geoip_sum = "https://example.invalid/geoip.sha256sum"
        geoip_url = "https://example.invalid/geoip.dat"
        site_sum = "https://example.invalid/dlc.sha256sum"
        site_url = "https://example.invalid/dlc.dat"
        geoip_payload = _bytes_of(sample_dataset())
        site_payload = _geosite_bytes()
        geoip_hash = hashlib.sha256(geoip_payload).hexdigest()
        site_hash = hashlib.sha256(site_payload).hexdigest()
        lock = {
            "datasets": [
                {
                    "filename": "geoip.dat",
                    "asset": "geoip.dat",
                    "tag": "202611080027",
                    "url": geoip_url,
                    "sha256sum_url": geoip_sum,
                    "sha256": geoip_hash,
                },
                {
                    "filename": "geosite.dat",
                    "asset": "dlc.dat",
                    "tag": "20261108011013",
                    "url": site_url,
                    "sha256sum_url": site_sum,
                    "sha256": site_hash,
                },
            ]
        }
        calls = []

        def mismatch(url):
            calls.append(url)
            if url == geoip_sum:
                return b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  geoip.dat\n"
            raise AssertionError(url)

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ChecksumMismatch) as caught:
                sync_datasets(lock, tmp, mismatch, log=lambda *_: None)
            self.assertIn("official aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", str(caught.exception))
            self.assertEqual(calls, [geoip_sum])
            self.assertEqual(list(Path(tmp).glob("*.dat")), [])

        calls.clear()
        bodies = {
            geoip_sum: f"{geoip_hash}  geoip.dat\n".encode(),
            geoip_url: geoip_payload,
            site_sum: f"{site_hash}  dlc.dat\n".encode(),
            site_url: site_payload,
        }

        def fetch(url):
            calls.append(url)
            return bodies[url]

        with tempfile.TemporaryDirectory() as tmp:
            installed = sync_datasets(lock, tmp, fetch, log=lambda *_: None)
            self.assertEqual([path.name for path in installed], ["geoip.dat", "geosite.dat"])
            self.assertEqual((Path(tmp) / "geosite.dat").read_bytes(), site_payload)
            self.assertEqual(list(Path(tmp).glob("*.partial")), [])
            calls.clear()
            sync_datasets(lock, tmp, fetch, log=lambda *_: None)
            self.assertEqual(calls, [geoip_sum, site_sum])

            def tamper(url):
                if url == geoip_url:
                    return b"not-the-dataset"
                return bodies[url]

            with self.assertRaises(ChecksumMismatch):
                sync_datasets(lock, Path(tmp) / "fresh", tamper, log=lambda *_: None)
            self.assertFalse((Path(tmp) / "fresh" / "geoip.dat").exists())

    def test_locked_load_rejects_bad_bytes(self):
        payload = b"tiny"
        digest = hashlib.sha256(payload).hexdigest()
        lock = {
            "version": 1,
            "source": "v2fly",
            "datasets": [
                {
                    "id": "geoip",
                    "filename": "geoip.dat",
                    "asset": "geoip.dat",
                    "tag": "1",
                    "url": "https://github.com/v2fly/geoip/releases/download/1/geoip.dat",
                    "sha256sum_url": "https://github.com/v2fly/geoip/releases/download/1/geoip.dat.sha256sum",
                    "sha256": digest,
                    "license": "CC-BY-SA-4.0",
                    "project": "https://github.com/v2fly/geoip",
                },
                {
                    "id": "geosite",
                    "filename": "geosite.dat",
                    "asset": "dlc.dat",
                    "tag": "1",
                    "url": "https://github.com/v2fly/domain-list-community/releases/download/1/dlc.dat",
                    "sha256sum_url": "https://github.com/v2fly/domain-list-community/releases/download/1/dlc.dat.sha256sum",
                    "sha256": digest,
                    "license": "MIT",
                    "project": "https://github.com/v2fly/domain-list-community",
                },
            ],
        }
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            lock_path = root / "lock.json"
            lock_path.write_text(json.dumps(lock), encoding="utf-8")
            with self.assertRaises(GeoDataError):
                load_locked_dataset(root / "data", lock_path)
            data = root / "data"
            data.mkdir()
            (data / "geoip.dat").write_bytes(payload)
            (data / "geosite.dat").write_bytes(b"other")
            with self.assertRaises(ChecksumMismatch):
                load_locked_dataset(data, lock_path)

    def test_sync_refuses_path_escape(self):
        lock = {"datasets": [{"filename": "../geoip.dat", "sha256sum_url": "https://example.invalid/sum"}]}
        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(GeoDataError):
                sync_datasets(lock, tmp, lambda url: (_ for _ in ()).throw(AssertionError(url)), log=lambda *_: None)

    def test_download_hosts_and_gitignore(self):
        with self.assertRaises(GeoDataError):
            _check_download_url("http://github.com/v2fly/geoip/releases/download/1/geoip.dat")
        with self.assertRaises(GeoDataError):
            _check_download_url("https://evil.example/geoip.dat")
        with self.assertRaises(GeoDataError):
            _check_download_url("https://objects.githubusercontent.com/geoip.dat", allow_cdn=False)
        _check_download_url("https://objects.githubusercontent.com/geoip.dat", allow_cdn=True)
        for relative in ("data/geo/geoip.dat", "data/geo/geosite.dat", "argus_settings.json"):
            result = subprocess.run(
                ["git", "check-ignore", "-q", relative],
                cwd=ROOT,
                check=False,
            )
            self.assertEqual(result.returncode, 0, relative)
        self.assertTrue((ROOT / "THIRD_PARTY_NOTICES.md").is_file())


def _geosite_bytes():
    return geosite_list([
        geosite_message("exact", [domain_message("www.example.com", 3)]),
        geosite_message("zone", [domain_message("example.com", 2)]),
        geosite_message("kw", [domain_message("ads", 0)]),
        geosite_message("svc", [domain_message(r"^svc-.+\.example\.com$", 1)]),
        geosite_message("skip", [domain_message("   ", 0)]),
    ])


def _bytes_of(_dataset):
    geoip = geoip_list([
        geoip_message("zz", [(packed("10.0.0.0"), 8)]),
        geoip_message("us", [(packed("10.1.2.0"), 24), (packed("10.1.2.9"), 32)]),
        geoip_message("cn", [(packed("10.1.2.9"), 32)]),
        geoip_message("nope", [(packed("0.0.0.0"), 0)], inverse=True),
        geoip_message("ts", [(ipaddress.ip_network("2001:db8::/32").network_address.packed, 32)]),
        geoip_message("mp", [(ipaddress.IPv6Address("::ffff:192.0.2.10").packed, 128)]),
        geoip_message("tx", [], inverse=False),
    ])
    text_cidr = vint_field(2, 32) + delimited(68000, b"198.51.100.7")
    geoip += delimited(1, text_field(1, "lab") + delimited(2, text_cidr))
    return geoip


if __name__ == "__main__":
    unittest.main()
