"""Loader for v2fly GeoIPList and GeoSiteList datasets.

The wire format is the v2ray-core routercommon protobuf
(GeoIPList / GeoSiteList). Country lookup uses forward CIDR matches.
Field 3 (inverse_match) is ignored for country assignment. Domain lookup
follows Plain, Regex, RootDomain, and Full rules. No third-party packages.
"""

import hashlib
import ipaddress
import json
import re
import urllib.parse
from pathlib import Path

_FORBIDDEN = ("loyalsoldier", "sing-box", "singbox")
_LOCK_SPEC = {
    "geoip": {
        "filename": "geoip.dat",
        "asset": "geoip.dat",
        "project_path": "v2fly/geoip",
        "license": "CC-BY-SA-4.0",
        "project": "https://github.com/v2fly/geoip",
    },
    "geosite": {
        "filename": "geosite.dat",
        "asset": "dlc.dat",
        "project_path": "v2fly/domain-list-community",
        "license": "MIT",
        "project": "https://github.com/v2fly/domain-list-community",
    },
}
_PLAIN = 0
_REGEX = 1
_ROOT = 2
_FULL = 3
_MAX_REGEX = 512


class GeoDataError(ValueError):
    """The geo dataset, lockfile, or checksum is not usable."""


class ChecksumMismatch(GeoDataError):
    def __init__(self, filename, lock=None, official=None, file_hash=None):
        self.filename = filename
        self.lock = lock
        self.official = official
        self.file_hash = file_hash
        parts = [f"{filename} checksum mismatch"]
        if lock is not None:
            parts.append(f"lockfile {lock}")
        if official is not None:
            parts.append(f"official {official}")
        if file_hash is not None:
            parts.append(f"file {file_hash}")
        super().__init__("; ".join(parts))


def repo_root():
    return Path(__file__).resolve().parents[1]


def default_data_dir():
    return repo_root() / "data" / "geo"


def default_lock_path():
    return repo_root() / "geo-datasets.lock.json"


def sha256_bytes(payload):
    return hashlib.sha256(payload).hexdigest()


def sha256_file(path):
    digest = hashlib.sha256()
    with open(path, "rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _validate_digest(digest):
    if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
        raise GeoDataError("sha256 digest must be 64 hex characters")
    return digest


def parse_sha256sum(text, expected_name=None):
    """Parse an upstream `sha256sum` asset. Match `expected_name` when the line has one."""
    if isinstance(text, bytes):
        text = text.decode("utf-8")
    chosen = None
    seen = False
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split()
        digest = _validate_digest(parts[0].lower())
        name = parts[1] if len(parts) > 1 else None
        seen = True
        if expected_name and name == expected_name:
            return digest
        if chosen is None and name is None and expected_name is None:
            chosen = digest
        elif chosen is None and expected_name is None:
            chosen = digest
    if not seen:
        raise GeoDataError("empty sha256sum")
    if expected_name:
        raise GeoDataError(f"sha256sum has no entry for {expected_name}")
    return chosen


def _release_url(project_path, tag, asset):
    return f"https://github.com/{project_path}/releases/download/{tag}/{asset}"


def validate_lockfile(data):
    if not isinstance(data, dict):
        raise GeoDataError("lockfile must be a JSON object")
    if data.get("source") != "v2fly":
        raise GeoDataError("lockfile source must be v2fly")
    entries = data.get("datasets")
    if not isinstance(entries, list) or len(entries) != 2:
        raise GeoDataError("lockfile must list geoip then geosite")
    if any(not isinstance(item, dict) for item in entries):
        raise GeoDataError("lockfile must list geoip then geosite")
    if [item.get("id") for item in entries] != ["geoip", "geosite"]:
        raise GeoDataError("lockfile must list geoip then geosite")
    cleaned = []
    for item in entries:
        for field in ("url", "sha256sum_url", "project", "filename", "asset"):
            text = str(item.get(field, "")).lower()
            for banned in _FORBIDDEN:
                if banned in text:
                    raise GeoDataError(f"{item['id']} must not reference {banned}")
        spec = _LOCK_SPEC[item["id"]]
        tag = str(item.get("tag", ""))
        if not tag.isdigit():
            raise GeoDataError(f"{item['id']} tag must be the numeric release tag")
        digest = _validate_digest(str(item.get("sha256", "")).lower())
        for key, expected in (
            ("filename", spec["filename"]),
            ("asset", spec["asset"]),
            ("license", spec["license"]),
            ("project", spec["project"]),
        ):
            if item.get(key) != expected:
                raise GeoDataError(f"{item['id']} {key} must be {expected}")
        url = _release_url(spec["project_path"], tag, spec["asset"])
        sum_url = url + ".sha256sum"
        if item.get("url") != url or item.get("sha256sum_url") != sum_url:
            raise GeoDataError(f"{item['id']} URL is not the pinned v2fly release asset")
        cleaned.append({
            "id": item["id"],
            "filename": spec["filename"],
            "asset": spec["asset"],
            "tag": tag,
            "url": url,
            "sha256sum_url": sum_url,
            "sha256": digest,
            "license": spec["license"],
            "project": spec["project"],
        })
    return {"version": data.get("version", 1), "source": "v2fly", "datasets": cleaned}


def load_lockfile(path=None):
    path = Path(path) if path else default_lock_path()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise GeoDataError(f"cannot read lockfile {path}: {exc}") from exc
    return validate_lockfile(data)


def _read_varint(buf, index):
    result = 0
    shift = 0
    size = len(buf)
    while shift <= 63:
        if index >= size:
            raise GeoDataError("truncated protobuf varint")
        byte = buf[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if not byte & 0x80:
            return result, index
        shift += 7
    raise GeoDataError("protobuf varint is too long")


def iter_fields(buf):
    """Yield (field_number, wire_type, value) for one protobuf message."""
    if not isinstance(buf, memoryview):
        buf = memoryview(buf)
    index = 0
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field_number = key >> 3
        wire = key & 7
        if field_number <= 0:
            raise GeoDataError("invalid protobuf field number")
        if wire == 0:
            value, index = _read_varint(buf, index)
        elif wire == 1:
            if index + 8 > size:
                raise GeoDataError("truncated protobuf fixed64")
            value = buf[index:index + 8]
            index += 8
        elif wire == 2:
            length, index = _read_varint(buf, index)
            if length < 0 or index + length > size:
                raise GeoDataError("truncated protobuf length-delimited field")
            value = buf[index:index + length]
            index += length
        elif wire == 5:
            if index + 4 > size:
                raise GeoDataError("truncated protobuf fixed32")
            value = buf[index:index + 4]
            index += 4
        else:
            raise GeoDataError(f"unsupported protobuf wire type {wire}")
        yield field_number, wire, value


def _decode_text(value):
    try:
        return bytes(value).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise GeoDataError("protobuf string is not utf-8") from exc


class GeoDataset:
    def __init__(self):
        self._v4 = {}
        self._v6 = {}
        self._full = {}
        self._root = {}
        self._plain = []
        self._regex = []
        self.counts = {"cidr_v4": 0, "cidr_v6": 0, "full": 0, "root": 0, "plain": 0, "regex": 0}

    @classmethod
    def from_bytes(cls, geoip, geosite):
        dataset = cls()
        dataset._load_geoip(geoip)
        dataset._load_geosite(geosite)
        return dataset

    @classmethod
    def from_files(cls, geoip_path, geosite_path):
        return cls.from_bytes(Path(geoip_path).read_bytes(), Path(geosite_path).read_bytes())

    def country_for_ip(self, ip):
        """Return the country or list code for an IP, or None when it is not covered."""
        try:
            addr = ipaddress.ip_address(str(ip).strip())
        except ValueError:
            return None
        if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
            addr = addr.ipv4_mapped
        if isinstance(addr, ipaddress.IPv4Address):
            return _lookup(int(addr), self._v4, 32)
        return _lookup(int(addr), self._v6, 128)

    def categories_for_domain(self, domain):
        """Return matching geosite category codes in dataset order."""
        host = _normalize_domain(domain)
        if not host:
            return []
        found = []
        seen = set()

        def add(categories):
            for category in categories:
                if category not in seen:
                    seen.add(category)
                    found.append(category)

        add(self._full.get(host, ()))
        labels = host.split(".")
        for start in range(len(labels)):
            add(self._root.get(".".join(labels[start:]), ()))
        for needle, category in self._plain:
            if needle in host:
                add((category,))
        for pattern, category in self._regex:
            if pattern.search(host):
                add((category,))
        return found

    def _load_geoip(self, payload):
        for field_number, wire, value in iter_fields(payload):
            if field_number != 1 or wire != 2:
                continue
            code, cidrs, inverse = _parse_geoip(value)
            if inverse or not code:
                continue
            for ip_bytes, prefix in cidrs:
                self._add_cidr(ip_bytes, prefix, code)

    def _load_geosite(self, payload):
        for field_number, wire, value in iter_fields(payload):
            if field_number != 1 or wire != 2:
                continue
            code, domains = _parse_geosite(value)
            if not code:
                continue
            for kind, domain in domains:
                self._add_domain(kind, domain, code)

    def _add_cidr(self, ip_bytes, prefix, country):
        if len(ip_bytes) == 16:
            mapped = ipaddress.IPv6Address(bytes(ip_bytes)).ipv4_mapped
            if mapped is not None:
                if prefix < 96 or prefix - 96 > 32:
                    raise GeoDataError("IPv4-mapped prefix is out of range")
                self._add_int(int(mapped), prefix - 96, 32, country, self._v4, "cidr_v4")
                return
        if len(ip_bytes) == 4:
            self._add_int(int.from_bytes(ip_bytes, "big"), prefix, 32, country, self._v4, "cidr_v4")
            return
        if len(ip_bytes) == 16:
            self._add_int(int.from_bytes(ip_bytes, "big"), prefix, 128, country, self._v6, "cidr_v6")
            return
        raise GeoDataError(f"CIDR address length {len(ip_bytes)} is not 4 or 16")

    def _add_int(self, ip_int, prefix, width, country, table, count_key):
        if prefix < 0 or prefix > width:
            raise GeoDataError(f"CIDR prefix {prefix} is outside 0..{width}")
        shift = width - prefix
        network = 0 if prefix == 0 else (ip_int >> shift) << shift
        bucket = table.get(prefix)
        if bucket is None:
            bucket = {}
            table[prefix] = bucket
        bucket.setdefault(network, country)
        self.counts[count_key] += 1

    def _add_domain(self, kind, domain, category):
        if kind == _FULL:
            _append_category(self._full, domain, category)
            self.counts["full"] += 1
        elif kind == _ROOT:
            _append_category(self._root, domain, category)
            self.counts["root"] += 1
        elif kind == _PLAIN:
            self._plain.append((domain, category))
            self.counts["plain"] += 1
        elif kind == _REGEX:
            if len(domain) > _MAX_REGEX:
                raise GeoDataError("geosite regex is too long")
            try:
                compiled = re.compile(domain, re.IGNORECASE)
            except re.error as exc:
                raise GeoDataError(f"geosite regex failed to compile: {exc}") from exc
            self._regex.append((compiled, category))
            self.counts["regex"] += 1
        else:
            raise GeoDataError(f"unknown geosite domain type {kind}")


def _append_category(index, key, category):
    current = index.get(key)
    if current is None:
        index[key] = [category]
    elif category not in current:
        current.append(category)


def _lookup(ip_int, table, width):
    for prefix in range(width, -1, -1):
        bucket = table.get(prefix)
        if not bucket:
            continue
        shift = width - prefix
        network = 0 if prefix == 0 else (ip_int >> shift) << shift
        country = bucket.get(network)
        if country is not None:
            return country
    return None


def _parse_geoip(payload):
    code = ""
    cidrs = []
    inverse = False
    for field_number, wire, value in iter_fields(payload):
        if field_number == 1 and wire == 2:
            code = _decode_text(value)
        elif field_number == 2 and wire == 2:
            cidrs.append(_parse_cidr(value))
        elif field_number == 3 and wire == 0:
            inverse = bool(value)
    return code, cidrs, inverse


def _parse_cidr(payload):
    ip_bytes = b""
    prefix = 0
    ip_text = None
    for field_number, wire, value in iter_fields(payload):
        if field_number == 1 and wire == 2:
            ip_bytes = bytes(value)
        elif field_number == 2 and wire == 0:
            prefix = value
        elif field_number == 68000 and wire == 2 and not ip_bytes:
            ip_text = _decode_text(value)
    if not ip_bytes and ip_text:
        try:
            ip_bytes = ipaddress.ip_address(ip_text).packed
        except ValueError as exc:
            raise GeoDataError(f"CIDR address {ip_text!r} is invalid") from exc
    if not ip_bytes:
        raise GeoDataError("CIDR is missing an address")
    return ip_bytes, prefix


def _parse_geosite(payload):
    code = ""
    domains = []
    for field_number, wire, value in iter_fields(payload):
        if field_number == 1 and wire == 2:
            code = _decode_text(value)
        elif field_number == 2 and wire == 2:
            parsed = _parse_domain(value)
            if parsed is not None:
                domains.append(parsed)
    return code, domains


def _parse_domain(payload):
    kind = _PLAIN
    value = ""
    for field_number, wire, raw in iter_fields(payload):
        if field_number == 1 and wire == 0:
            kind = raw
        elif field_number == 2 and wire == 2:
            value = _decode_text(raw)
    if kind == _REGEX:
        text = value.strip()
        return (kind, text) if text else None
    text = value.strip().rstrip(".").casefold()
    if text.startswith("."):
        text = text[1:]
    if not text:
        return None
    return kind, text


def _normalize_domain(domain):
    if domain is None:
        return ""
    text = str(domain).strip()
    if not text:
        return ""
    if "://" in text:
        host = urllib.parse.urlparse(text).hostname
        text = host or ""
    else:
        text = text.split("/")[0]
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        elif text.count(":") == 1:
            host, port = text.rsplit(":", 1)
            if port.isdigit():
                text = host
    text = text.strip().rstrip(".").casefold()
    if not text or len(text) > 253:
        return ""
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return text
    return ""


def load_locked_dataset(data_dir=None, lock_path=None):
    """Load data/geo/*.dat after the on-disk bytes match the lockfile SHA-256."""
    lock = load_lockfile(lock_path)
    data_dir = Path(data_dir) if data_dir else default_data_dir()
    paths = []
    for entry in lock["datasets"]:
        path = data_dir / entry["filename"]
        if not path.is_file():
            raise GeoDataError(
                f"missing {path}. Run scripts/fetch_geo_dat.py to download the pinned v2fly sets."
            )
        actual = sha256_file(path)
        if actual != entry["sha256"]:
            raise ChecksumMismatch(entry["filename"], lock=entry["sha256"], file_hash=actual)
        paths.append(path)
    return GeoDataset.from_files(paths[0], paths[1])


class GeoAnnotator:
    """Advisory cyber annotation. Does not change tracks, alerts, or recommendations."""

    def __init__(self, dataset):
        self.dataset = dataset
        self._entries = []

    def annotate(self, observations):
        for obs in observations:
            if not isinstance(obs, dict):
                continue
            ip = _first_text(obs, "source_ip", "ip")
            domain = _first_text(obs, "domain", "host")
            if not ip and not domain:
                continue
            entry = {}
            detection = obs.get("detection_id")
            if detection:
                entry["detection_id"] = detection
            if ip:
                entry["source_ip"] = ip
                entry["country"] = self.dataset.country_for_ip(ip)
            if domain:
                entry["domain"] = domain
                entry["categories"] = self.dataset.categories_for_domain(domain)
            entry["action"] = "annotate"
            self._entries.append(entry)
        return {
            "enabled": True,
            "policy": "advisory-annotate",
            "entries": [_copy_entry(entry) for entry in self._entries],
        }


def _first_text(obs, *keys):
    for key in keys:
        value = obs.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return None


def _copy_entry(entry):
    copied = dict(entry)
    if "categories" in copied:
        copied["categories"] = list(copied["categories"])
    return copied
