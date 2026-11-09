"""Download the pinned v2fly geoip.dat and geosite.dat releases.

The binaries are written under data/geo/ and must stay untracked.
A checksum mismatch against the official .sha256sum asset or geo.lock.json
aborts before the destination file is replaced.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import urllib.error
import urllib.request
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_LOCKFILE = REPO_ROOT / "geo.lock.json"
DEFAULT_OUTPUT = REPO_ROOT / "data" / "geo"
MAX_DATASET_BYTES = 64 * 1024 * 1024
MAX_SUM_BYTES = 4096
ALLOWED_PREFIXES = (
    "https://github.com/v2fly/geoip/releases/download/",
    "https://github.com/v2fly/domain-list-community/releases/download/",
)
ALLOWED_REDIRECT_HOSTS = (
    "release-assets.githubusercontent.com",
    "objects.githubusercontent.com",
    "github.com",
)
ALLOWED_FILENAMES = ("geoip.dat", "geosite.dat")


class ChecksumMismatch(Exception):
    """Official sha256sum, lockfile hash, and downloaded bytes disagreed."""


def load_lockfile(path: Path | None = None) -> dict:
    lock_path = Path(path) if path else DEFAULT_LOCKFILE
    with lock_path.open(encoding="utf-8") as handle:
        data = json.load(handle)
    if not isinstance(data, dict) or not isinstance(data.get("datasets"), list):
        raise ValueError(f"{lock_path} is missing a datasets list")
    return data


def parse_sha256sum(text: str) -> str:
    """Return the hex digest from a coreutils .sha256sum document."""
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        token = stripped.split()[0].lower()
        if len(token) == 64 and all(char in "0123456789abcdef" for char in token):
            return token
    raise ValueError("sha256sum asset does not contain a SHA-256 digest")


def verify_digest(blob: bytes, expected: str) -> str:
    digest = hashlib.sha256(blob).hexdigest()
    if digest != expected.lower():
        raise ChecksumMismatch(
            f"downloaded bytes hash to {digest}, expected {expected.lower()}"
        )
    return digest


def confirm_official(official_text: str, locked: str) -> str:
    official = parse_sha256sum(official_text)
    if official != locked.lower():
        raise ChecksumMismatch(
            f"official sha256sum {official} does not match lockfile {locked.lower()}"
        )
    return official


def check_source_url(url: str) -> None:
    if any(url.startswith(prefix) for prefix in ALLOWED_PREFIXES):
        return
    raise ValueError(f"refusing URL outside the pinned v2fly releases: {url}")


def _check_redirect(url: str) -> None:
    parsed = urllib.request.urlparse(url)
    if parsed.scheme != "https" or parsed.hostname not in ALLOWED_REDIRECT_HOSTS:
        raise ValueError(f"refusing redirect to {url}")


class _RedirectGuard(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        _check_redirect(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def download(url: str, limit: int = MAX_DATASET_BYTES) -> bytes:
    check_source_url(url)
    request = urllib.request.Request(url, headers={"User-Agent": "infinitum-geo-fetch/1.0"})
    opener = urllib.request.build_opener(_RedirectGuard)
    with opener.open(request, timeout=120) as response:
        chunks: list[bytes] = []
        total = 0
        while True:
            block = response.read(256 * 1024)
            if not block:
                break
            total += len(block)
            if total > limit:
                raise ValueError(f"download exceeds {limit} bytes: {url}")
            chunks.append(block)
    return b"".join(chunks)


def _safe_filename(name: str) -> str:
    if name not in ALLOWED_FILENAMES or Path(name).name != name:
        raise ValueError(f"unexpected dataset filename: {name}")
    return name


def _write_verified(dest: Path, blob: bytes, digest: str) -> None:
    verify_digest(blob, digest)
    dest.parent.mkdir(parents=True, exist_ok=True)
    partial = dest.with_name(dest.name + ".partial")
    try:
        partial.write_bytes(blob)
        verify_digest(partial.read_bytes(), digest)
        os.replace(partial, dest)
    except Exception:
        partial.unlink(missing_ok=True)
        raise


def fetch_all(lock: dict, output: Path, downloader=download) -> list[Path]:
    written: list[Path] = []
    for item in lock["datasets"]:
        filename = _safe_filename(item["filename"])
        url = item["url"]
        sum_url = item["sha256sum_url"]
        locked = item["sha256"]
        check_source_url(url)
        check_source_url(sum_url)
        try:
            official = confirm_official(
                downloader(sum_url, MAX_SUM_BYTES).decode("utf-8", "replace"),
                locked,
            )
        except ChecksumMismatch as exc:
            raise ChecksumMismatch(f"{filename}: {exc}") from exc
        blob = downloader(url, MAX_DATASET_BYTES)
        dest = Path(output) / filename
        try:
            _write_verified(dest, blob, official)
        except ChecksumMismatch as exc:
            raise ChecksumMismatch(f"{filename}: {exc}") from exc
        written.append(dest)
    return written


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Fetch pinned v2fly geoip.dat and geosite.dat")
    parser.add_argument("--lockfile", type=Path, default=DEFAULT_LOCKFILE)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args(argv)
    try:
        paths = fetch_all(load_lockfile(args.lockfile), args.output)
    except (ChecksumMismatch, ValueError, OSError, urllib.error.URLError) as exc:
        print(f"geo fetch failed: {exc}", flush=True)
        return 1
    for path in paths:
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        print(f"verified {path.name} {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
