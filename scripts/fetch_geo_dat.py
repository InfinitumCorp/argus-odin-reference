#!/usr/bin/env python3
"""Download pinned v2fly geoip.dat and geosite.dat into the gitignored data directory.

Each payload is checked against the lockfile SHA-256 and the official .sha256sum
asset. A mismatch stops the run and does not install that file.
"""

import sys
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from argus.geo import (  # noqa: E402
    ChecksumMismatch,
    GeoDataError,
    default_data_dir,
    default_lock_path,
    load_lockfile,
    parse_sha256sum,
    sha256_bytes,
    sha256_file,
)

MAX_BYTES = 80 * 1024 * 1024
ALLOWED_HOSTS = {
    "github.com",
    "objects.githubusercontent.com",
    "release-assets.githubusercontent.com",
    "github-releases.githubusercontent.com",
}


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_download_url(newurl, allow_cdn=True)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def _check_download_url(url, allow_cdn=False):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or ""
    allowed = ALLOWED_HOSTS if allow_cdn else {"github.com"}
    if parsed.scheme != "https" or host not in allowed:
        raise GeoDataError(f"refusing download URL {url}")


def fetch_bytes(url, timeout=120):
    _check_download_url(url, allow_cdn=False)
    request = urllib.request.Request(url, headers={"User-Agent": "argus-geo-fetch/1"})
    opener = urllib.request.build_opener(_SafeRedirect)
    with opener.open(request, timeout=timeout) as response:
        _check_download_url(response.geturl(), allow_cdn=True)
        chunks = []
        total = 0
        while True:
            block = response.read(1024 * 1024)
            if not block:
                break
            total += len(block)
            if total > MAX_BYTES:
                raise GeoDataError("download exceeded the size cap")
            chunks.append(block)
        return b"".join(chunks)


def sync_datasets(lock, dest, fetcher, log=print):
    """Download lock entries. `fetcher(url) -> bytes`. Raise ChecksumMismatch and stop."""
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    installed = []
    for entry in lock["datasets"]:
        filename = entry["filename"]
        if filename != Path(filename).name or not filename.endswith(".dat"):
            raise GeoDataError(f"refusing dataset filename {filename}")
        official_text = fetcher(entry["sha256sum_url"])
        official = parse_sha256sum(official_text, entry["asset"])
        if official != entry["sha256"]:
            raise ChecksumMismatch(entry["filename"], lock=entry["sha256"], official=official)
        target = dest / filename
        if target.is_file() and sha256_file(target) == official:
            log(f"{entry['filename']} tag {entry['tag']} sha256 {official} ok")
            installed.append(target)
            continue
        payload = fetcher(entry["url"])
        actual = sha256_bytes(payload)
        if actual != official:
            raise ChecksumMismatch(
                entry["filename"], lock=entry["sha256"], official=official, file_hash=actual
            )
        partial = dest / f"{filename}.partial"
        partial.write_bytes(payload)
        written = sha256_file(partial)
        if written != official:
            partial.unlink(missing_ok=True)
            raise ChecksumMismatch(
                entry["filename"], lock=entry["sha256"], official=official, file_hash=written
            )
        partial.replace(target)
        log(f"{entry['filename']} tag {entry['tag']} sha256 {official} ok")
        installed.append(target)
    return installed


def main(argv=None):
    import argparse

    parser = argparse.ArgumentParser(prog="fetch_geo_dat.py")
    parser.add_argument("--lock", type=Path, default=None, help="Path to geo-datasets.lock.json")
    parser.add_argument("--dest", type=Path, default=None, help="Directory for geoip.dat and geosite.dat")
    args = parser.parse_args(sys.argv[1:] if argv is None else argv)
    try:
        lock = load_lockfile(args.lock or default_lock_path())
        sync_datasets(lock, args.dest or default_data_dir(), fetch_bytes)
    except ChecksumMismatch as exc:
        print(f"checksum mismatch: {exc}", file=sys.stderr)
        print("stopped before installing a file that does not match the official sha256sum", file=sys.stderr)
        return 1
    except GeoDataError as exc:
        print(f"geo fetch failed: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"geo fetch failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
