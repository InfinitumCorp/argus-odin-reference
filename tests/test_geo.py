"""Synthetic GeoIPList / GeoSiteList coverage and the opt-in picture hook."""

from __future__ import annotations

import hashlib
import os
import sys
import tempfile
import unittest
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus.fusion import ArgusFusionEngine
from argus.geo import GEO_POLICY, GeoData, apply_geo_hook, geo_enabled, load_geo_data
from argus.geo_fetch import (
    ChecksumMismatch,
    check_source_url,
    confirm_official,
    fetch_all,
    load_lockfile,
    parse_sha256sum,
    verify_digest,
)
from tests.dat_codec import synthetic_geoip, synthetic_geosite

FIXTURES = ROOT / "tests" / "fixtures"
LOCKED_GEOIP = "eedb24b3b9fcba27e06b92c0428dab90d9496083091ae4cf39e11387fd99d0e2"
LOCKED_GEOSITE = "dc4192dd1b644a38276ed06136d26e729fa674d25785adb38c87e040e92376b2"
PICTURE_KEYS = {
    "timestamp",
    "track_count",
    "alert_count",
    "tracks",
    "defense_alerts",
    "spectrum",
    "forecasts",
}

# Hand-built GeoIPList: US 8.8.8.0/24. Independent of tests/dat_codec.py.
HAND_GEOIP = bytes.fromhex("0a0e0a02555312080a04080808001018")
# Hand-built GeoSiteList: GOOGLE root domain google.com.
HAND_GEOSITE = bytes.fromhex(
    "0a180a06474f4f474c45120e0802120a676f6f676c652e636f6d"
)


@contextmanager
def patched_env(**values):
    previous = {key: os.environ.get(key) for key in values}
    for key, value in values.items():
        if value is None:
            os.environ.pop(key, None)
        else:
            os.environ[key] = value
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def picture_shape(picture):
    return {
        "tracks": sorted(
            (track["classification"], track["is_threat"], track["explanation"])
            for track in picture["tracks"]
        ),
        "alerts": [
            (alert["threat_type"], alert["recommendation"], alert["explanation"])
            for alert in picture["defense_alerts"]
        ],
        "forecasts": picture["forecasts"],
        "spectrum": picture["spectrum"],
    }


class DecoderTests(unittest.TestCase):
    def test_hand_built_geoip_and_geosite(self):
        data = GeoData(HAND_GEOIP, HAND_GEOSITE)
        self.assertEqual(data.lookup_ip("8.8.8.8"), "US")
        self.assertIsNone(data.lookup_ip("1.1.1.1"))
        self.assertEqual(data.lookup_domain("www.google.com"), ["GOOGLE"])
        self.assertEqual(data.lookup_domain("notgoogle.com"), [])

    def test_synthetic_fixtures_match_encoder(self):
        self.assertEqual((FIXTURES / "synthetic_geoip.dat").read_bytes(), synthetic_geoip())
        self.assertEqual((FIXTURES / "synthetic_geosite.dat").read_bytes(), synthetic_geosite())

    def test_fixture_lookups(self):
        data = GeoData(
            (FIXTURES / "synthetic_geoip.dat").read_bytes(),
            (FIXTURES / "synthetic_geosite.dat").read_bytes(),
        )
        self.assertEqual(data.lookup_ip("8.8.8.8"), "US")
        self.assertEqual(data.lookup_ip("1.2.3.4"), "CA")
        self.assertEqual(data.lookup_ip("1.2.9.1"), "US")
        self.assertEqual(data.lookup_ip("10.1.2.3"), "PRIVATE")
        self.assertEqual(data.lookup_ip("203.0.113.9"), "TESTNET")
        self.assertIsNone(data.lookup_ip("192.0.2.10"))
        self.assertEqual(data.lookup_ip("2001:db8:1::5"), "US")
        self.assertIsNone(data.lookup_ip("2001:db8:2::5"))
        self.assertIsNone(data.lookup_ip("not-an-ip"))
        self.assertEqual(data.lookup_domain("WWW.Google.com"), ["GOOGLE"])
        self.assertEqual(data.lookup_domain("https://dns.google/path"), ["GOOGLE"])
        self.assertEqual(data.lookup_domain("ads.doubleclick.net"), ["ADS"])
        self.assertEqual(data.lookup_domain("foo.news"), ["NEWS"])
        self.assertEqual(data.lookup_domain("www.example.cn"), ["CN"])
        self.assertEqual(data.lookup_domain("notgoogle.com"), [])
        self.assertEqual(data.lookup_domain(""), [])

    def test_truncated_dat_raises(self):
        with self.assertRaises(ValueError):
            GeoData(b"\x0a\x10", b"")


class FetchTests(unittest.TestCase):
    def test_lockfile_pins_v2fly_releases(self):
        lock = load_lockfile(ROOT / "geo.lock.json")
        by_name = {item["filename"]: item for item in lock["datasets"]}
        self.assertEqual(by_name["geoip.dat"]["sha256"], LOCKED_GEOIP)
        self.assertEqual(by_name["geoip.dat"]["tag"], "202611080027")
        self.assertEqual(by_name["geoip.dat"]["asset"], "geoip.dat")
        self.assertTrue(by_name["geoip.dat"]["url"].startswith("https://github.com/v2fly/geoip/"))
        self.assertEqual(by_name["geosite.dat"]["sha256"], LOCKED_GEOSITE)
        self.assertEqual(by_name["geosite.dat"]["tag"], "20261108011013")
        self.assertEqual(by_name["geosite.dat"]["asset"], "dlc.dat")
        self.assertTrue(by_name["geosite.dat"]["url"].endswith("/dlc.dat"))
        self.assertIn("data/geo/", (ROOT / ".gitignore").read_text())
        notices = (ROOT / "THIRD_PARTY_NOTICES").read_text()
        self.assertIn(LOCKED_GEOIP, notices)
        self.assertIn(LOCKED_GEOSITE, notices)
        self.assertIn("CC-BY-SA-4.0", notices)
        self.assertIn("Copyright (c) 2018-2019 V2Ray", notices)

    def test_parse_and_verify_digest(self):
        digest = hashlib.sha256(b"abc").hexdigest()
        self.assertEqual(parse_sha256sum(f"{digest.upper()} *example.dat\n"), digest)
        self.assertEqual(verify_digest(b"abc", digest), digest)
        with self.assertRaises(ChecksumMismatch):
            verify_digest(b"abd", digest)

    def test_official_sum_mismatch_stops(self):
        with self.assertRaises(ChecksumMismatch):
            confirm_official("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  geoip.dat\n", LOCKED_GEOIP)

    def test_fetch_rejects_unpinned_urls(self):
        with self.assertRaises(ValueError):
            check_source_url("http://github.com/v2fly/geoip/releases/download/x/geoip.dat")
        with self.assertRaises(ValueError):
            check_source_url("https://example.com/geoip.dat")

    def test_fetch_writes_only_after_checksum_match(self):
        blob = b"synthetic-bytes"
        digest = hashlib.sha256(blob).hexdigest()
        lock = {
            "datasets": [
                {
                    "filename": "geosite.dat",
                    "url": "https://github.com/v2fly/domain-list-community/releases/download/20261108011013/dlc.dat",
                    "sha256sum_url": "https://github.com/v2fly/domain-list-community/releases/download/20261108011013/dlc.dat.sha256sum",
                    "sha256": digest,
                }
            ]
        }

        def fake(url, limit):
            if url.endswith(".sha256sum"):
                return f"{digest}  dlc.dat\n".encode()
            return blob

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "ok"
            written = fetch_all(lock, output, downloader=fake)
            self.assertEqual(written[0].read_bytes(), blob)
            self.assertEqual(written[0].name, "geosite.dat")

    def test_fetch_mismatch_does_not_leave_a_binary(self):
        digest = hashlib.sha256(b"wanted").hexdigest()
        lock = {
            "datasets": [
                {
                    "filename": "geoip.dat",
                    "url": "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat",
                    "sha256sum_url": "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat.sha256sum",
                    "sha256": digest,
                }
            ]
        }

        def fake(url, limit):
            if url.endswith(".sha256sum"):
                return f"{digest}  geoip.dat\n".encode()
            return b"actual-different"

        with tempfile.TemporaryDirectory() as tmp:
            output = Path(tmp) / "bad"
            with self.assertRaises(ChecksumMismatch):
                fetch_all(lock, output, downloader=fake)
            self.assertFalse((output / "geoip.dat").exists())
            self.assertFalse((output / "geoip.dat.partial").exists())

    def test_official_mismatch_does_not_download_the_binary(self):
        lock = {
            "datasets": [
                {
                    "filename": "geoip.dat",
                    "url": "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat",
                    "sha256sum_url": "https://github.com/v2fly/geoip/releases/download/202611080027/geoip.dat.sha256sum",
                    "sha256": LOCKED_GEOIP,
                }
            ]
        }
        calls = []

        def fake(url, limit):
            calls.append(url)
            return b"0000000000000000000000000000000000000000000000000000000000000000  geoip.dat\n"

        with tempfile.TemporaryDirectory() as tmp:
            with self.assertRaises(ChecksumMismatch):
                fetch_all(lock, Path(tmp), downloader=fake)
        self.assertEqual(len(calls), 1)
        self.assertTrue(calls[0].endswith(".sha256sum"))


class HookTests(unittest.TestCase):
    def tearDown(self):
        os.environ.pop("INFINITUM_GEO_ENABLED", None)
        os.environ.pop("INFINITUM_GEO_DIR", None)

    def test_flag_defaults_off(self):
        with patched_env(INFINITUM_GEO_ENABLED=None):
            self.assertFalse(geo_enabled())
        for value in ("", "0", "false", "no", "off"):
            with patched_env(INFINITUM_GEO_ENABLED=value):
                self.assertFalse(geo_enabled())

    def test_hook_off_does_not_touch_the_picture(self):
        picture = {"tracks": [], "defense_alerts": []}
        observations = [{"detection_id": "OBS-1", "ip": "8.8.8.8", "domain": "www.google.com"}]
        with patched_env(INFINITUM_GEO_ENABLED=None, INFINITUM_GEO_DIR="/missing/geo"):
            returned = apply_geo_hook(picture, observations)
        self.assertIs(returned, picture)
        self.assertNotIn("geo", picture)

    def test_hook_on_annotates_without_changing_decisions(self):
        observations = [
            {
                "detection_id": "OBS-9",
                "sensor": "POLLEN-SWARM-01",
                "lat": 38.9,
                "lon": -77.0,
                "raw_class": "uas",
                "confidence": 0.9,
                "ip": "1.2.3.4",
                "domain": "www.google.com",
            }
        ]
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            (folder / "geoip.dat").write_bytes(synthetic_geoip())
            (folder / "geosite.dat").write_bytes(synthetic_geosite())
            with patched_env(INFINITUM_GEO_ENABLED=None, INFINITUM_GEO_DIR=str(folder)):
                off = ArgusFusionEngine().ingest_and_fuse(observations)
            with patched_env(INFINITUM_GEO_ENABLED="1", INFINITUM_GEO_DIR=str(folder)):
                with self.assertLogs("argus.geo", level="INFO") as captured:
                    on = ArgusFusionEngine().ingest_and_fuse(observations)
        self.assertNotIn("geo", off)
        self.assertEqual(set(off), PICTURE_KEYS)
        self.assertEqual(picture_shape(off), picture_shape({key: on[key] for key in PICTURE_KEYS}))
        self.assertEqual(on["geo"]["policy"], GEO_POLICY)
        self.assertEqual(on["geo"]["annotations"][0]["detection_id"], "OBS-9")
        self.assertEqual(on["geo"]["annotations"][0]["addresses"][0]["country"], "CA")
        self.assertEqual(on["geo"]["annotations"][0]["domains"][0]["categories"], ["GOOGLE"])
        self.assertTrue(any("cyber geo annotated" in line for line in captured.output))
        for alert in on["defense_alerts"]:
            self.assertIn("Advisory", alert["recommendation"])

    def test_enabled_engine_uses_directory(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            (directory / "geoip.dat").write_bytes(synthetic_geoip())
            (directory / "geosite.dat").write_bytes(synthetic_geosite())
            observations = [{"ip": "10.9.8.7", "host": "foo.news", "sensor": "S", "lat": 1.0, "lon": 2.0}]
            with patched_env(INFINITUM_GEO_ENABLED="yes", INFINITUM_GEO_DIR=str(directory)):
                picture = ArgusFusionEngine().ingest_and_fuse(observations)
                again = load_geo_data(directory)
                cached = load_geo_data(directory)
        note = picture["geo"]["annotations"][0]
        self.assertEqual(note["addresses"][0]["country"], "PRIVATE")
        self.assertEqual(note["domains"][0]["categories"], ["NEWS"])
        self.assertIs(again, cached)

    def test_missing_datasets_do_not_change_tracks(self):
        observations = [{"lat": 1, "lon": 2, "sensor": "S", "raw_class": "person", "ip": "8.8.8.8"}]
        with patched_env(INFINITUM_GEO_ENABLED="true", INFINITUM_GEO_DIR=str(ROOT / "missing-geo-dir")):
            with self.assertLogs("argus.geo", level="ERROR") as captured:
                picture = ArgusFusionEngine().ingest_and_fuse(observations)
        self.assertIn("error", picture["geo"])
        self.assertEqual(picture["geo"]["annotations"], [])
        self.assertEqual(picture["geo"]["policy"], GEO_POLICY)
        self.assertTrue(any("unavailable" in line for line in captured.output))
        self.assertIn("tracks", picture)

    def test_disabled_logs_nothing(self):
        picture = {"tracks": []}
        with patched_env(INFINITUM_GEO_ENABLED="0"):
            with self.assertNoLogs("argus.geo", level="INFO"):
                apply_geo_hook(picture, [{"ip": "8.8.8.8"}])


if __name__ == "__main__":
    unittest.main()
