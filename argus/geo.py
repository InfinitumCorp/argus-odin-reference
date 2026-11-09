"""Loader for v2ray GeoIPList and GeoSiteList datasets.

geoip.dat maps an address to a country or network code.
geosite.dat maps a domain to category codes.
Both files are protobuf messages from the v2fly router schema.
Nothing here is consulted unless INFINITUM_GEO_ENABLED is turned on.
"""

from __future__ import annotations

import ipaddress
import logging
import os
import re
import urllib.parse
from pathlib import Path

logger = logging.getLogger("argus.geo")

REPO_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_GEO_DIR = REPO_ROOT / "data" / "geo"
_TRUE_VALUES = {"1", "true", "yes", "on"}
_MAX_REGEX_LENGTH = 256

GEO_POLICY = (
    "Geo labels are advisory cyber context. "
    "They do not change classification, alerts, forecasts, or recommendations."
)

IP_FIELDS = ("ip", "src_ip", "dst_ip", "source_ip")
DOMAIN_FIELDS = ("domain", "host", "hostname")

_cache_key: tuple | None = None
_cache_value: "GeoData | None" = None


def geo_enabled(env: dict | None = None) -> bool:
    source = os.environ if env is None else env
    return source.get("INFINITUM_GEO_ENABLED", "").strip().lower() in _TRUE_VALUES


def geo_directory(env: dict | None = None) -> Path:
    source = os.environ if env is None else env
    override = source.get("INFINITUM_GEO_DIR", "").strip()
    if override:
        return Path(override)
    return DEFAULT_GEO_DIR


def _read_varint(buf: bytes, index: int) -> tuple[int, int]:
    shift = 0
    result = 0
    size = len(buf)
    while index < size:
        byte = buf[index]
        index += 1
        result |= (byte & 0x7F) << shift
        if byte < 0x80:
            return result, index
        shift += 7
        if shift > 63:
            raise ValueError("protobuf varint exceeds 64 bits")
    raise ValueError("truncated protobuf varint")


def _iter_fields(buf: bytes):
    index = 0
    size = len(buf)
    while index < size:
        key, index = _read_varint(buf, index)
        field, wire = key >> 3, key & 7
        if field == 0:
            raise ValueError("protobuf field number is zero")
        if wire == 0:
            value, index = _read_varint(buf, index)
        elif wire == 1:
            if index + 8 > size:
                raise ValueError("truncated protobuf fixed64")
            value = buf[index:index + 8]
            index += 8
        elif wire == 2:
            length, index = _read_varint(buf, index)
            if length < 0 or index + length > size:
                raise ValueError("truncated protobuf length field")
            value = buf[index:index + length]
            index += length
        elif wire == 5:
            if index + 4 > size:
                raise ValueError("truncated protobuf fixed32")
            value = buf[index:index + 4]
            index += 4
        else:
            raise ValueError(f"unsupported protobuf wire type {wire}")
        yield field, wire, value


def _network(raw: int, prefix: int, bits: int) -> int:
    if prefix <= 0:
        return 0
    if prefix >= bits:
        return raw
    space = (1 << bits) - 1
    mask = (space << (bits - prefix)) & space
    return raw & mask


class _PrefixIndex:
    def __init__(self, bits: int):
        self.bits = bits
        self._buckets: dict[int, dict[int, str]] = {}
        self._order: list[int] = []

    def add(self, raw: int, prefix: int, code: str) -> None:
        if prefix < 0 or prefix > self.bits or not code:
            return
        network = _network(raw, prefix, self.bits)
        self._buckets.setdefault(prefix, {}).setdefault(network, code)

    def freeze(self) -> None:
        self._order = sorted(self._buckets, reverse=True)

    def lookup(self, raw: int) -> str | None:
        for prefix in self._order:
            network = _network(raw, prefix, self.bits)
            code = self._buckets[prefix].get(network)
            if code:
                return code
        return None

    def contains(self, raw: int) -> bool:
        return self.lookup(raw) is not None

    @property
    def empty(self) -> bool:
        return not self._buckets


class GeoData:
    """In-memory indexes for one GeoIPList and one GeoSiteList.

    An address matches the longest prefix. When two lists share that prefix,
    the earlier GeoIP entry is kept. A domain can match more than one category.
    """

    def __init__(self, geoip: bytes, geosite: bytes):
        self.ipv4 = _PrefixIndex(32)
        self.ipv6 = _PrefixIndex(128)
        self._inverse: list[tuple[str, _PrefixIndex, _PrefixIndex]] = []
        self._full: dict[str, list[str]] = {}
        self._root: dict[str, list[str]] = {}
        self._plain: list[tuple[str, str]] = []
        self._regex: list[tuple[re.Pattern[str], str]] = []
        self._load_geoip(geoip)
        self._load_geosite(geosite)
        self.ipv4.freeze()
        self.ipv6.freeze()
        for _code, ipv4, ipv6 in self._inverse:
            ipv4.freeze()
            ipv6.freeze()

    def _load_geoip(self, blob: bytes) -> None:
        for field, wire, value in _iter_fields(blob):
            if field != 1 or wire != 2:
                continue
            code_raw = b""
            inverse = False
            cidrs: list[tuple[bytes, int]] = []
            for inner_field, inner_wire, inner in _iter_fields(value):
                if inner_field == 1 and inner_wire == 2:
                    code_raw += inner
                elif inner_field == 2 and inner_wire == 2:
                    cidrs.append(_parse_cidr(inner))
                elif inner_field == 3 and inner_wire == 0:
                    inverse = bool(inner)
            code = _decode_text(code_raw)
            if not code:
                continue
            if inverse:
                ipv4 = _PrefixIndex(32)
                ipv6 = _PrefixIndex(128)
                _fill_index(ipv4, ipv6, code, cidrs)
                self._inverse.append((code, ipv4, ipv6))
            else:
                _fill_index(self.ipv4, self.ipv6, code, cidrs)

    def _load_geosite(self, blob: bytes) -> None:
        for field, wire, value in _iter_fields(blob):
            if field != 1 or wire != 2:
                continue
            code_raw = b""
            domains: list[tuple[int, str]] = []
            for inner_field, inner_wire, inner in _iter_fields(value):
                if inner_field == 1 and inner_wire == 2:
                    code_raw += inner
                elif inner_field == 2 and inner_wire == 2:
                    domains.append(_parse_domain(inner))
            code = _decode_text(code_raw)
            if not code:
                continue
            for kind, name in domains:
                if not name:
                    continue
                if kind == 0:
                    self._plain.append((name, code))
                elif kind == 1:
                    pattern = _compile_domain_regex(name)
                    if pattern is not None:
                        self._regex.append((pattern, code))
                elif kind == 2:
                    self._root.setdefault(name, []).append(code)
                elif kind == 3:
                    self._full.setdefault(name, []).append(code)

    def lookup_ip(self, value: str) -> str | None:
        try:
            address = ipaddress.ip_address(value.strip())
        except (ValueError, AttributeError):
            return None
        raw = int(address)
        positive = self.ipv4.lookup(raw) if address.version == 4 else self.ipv6.lookup(raw)
        if positive:
            return positive
        for code, ipv4, ipv6 in self._inverse:
            index = ipv4 if address.version == 4 else ipv6
            if index.empty:
                continue
            if not index.contains(raw):
                return code
        return None

    def lookup_domain(self, value: str) -> list[str]:
        domain = normalize_domain(value)
        if not domain:
            return []
        found: list[str] = []
        seen: set[str] = set()

        def add(code: str) -> None:
            if code not in seen:
                seen.add(code)
                found.append(code)

        for code in self._full.get(domain, ()):
            add(code)
        labels = domain.split(".")
        for start in range(len(labels)):
            suffix = ".".join(labels[start:])
            for code in self._root.get(suffix, ()):
                add(code)
        for needle, code in self._plain:
            if needle in domain:
                add(code)
        for pattern, code in self._regex:
            if pattern.search(domain):
                add(code)
        return found


def _decode_text(raw: bytes) -> str:
    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError:
        return ""


def _parse_cidr(blob: bytes) -> tuple[bytes, int]:
    ip = b""
    prefix = 0
    for field, wire, value in _iter_fields(blob):
        if field == 1 and wire == 2:
            ip += value
        elif field == 2 and wire == 0:
            prefix = int(value)
    return ip, prefix


def _fill_index(ipv4: _PrefixIndex, ipv6: _PrefixIndex, code: str, cidrs: list[tuple[bytes, int]]) -> None:
    for ip, prefix in cidrs:
        if len(ip) == 4 and 0 <= prefix <= 32:
            ipv4.add(int.from_bytes(ip, "big"), prefix, code)
        elif len(ip) == 16 and 0 <= prefix <= 128:
            ipv6.add(int.from_bytes(ip, "big"), prefix, code)


def _parse_domain(blob: bytes) -> tuple[int, str]:
    kind = 0
    raw_value = b""
    for field, wire, raw in _iter_fields(blob):
        if field == 1 and wire == 0:
            kind = int(raw)
        elif field == 2 and wire == 2:
            raw_value += raw
    value = _decode_text(raw_value).strip().lower().rstrip(".")
    return kind, value


def _compile_domain_regex(pattern: str) -> re.Pattern[str] | None:
    if not pattern or len(pattern) > _MAX_REGEX_LENGTH:
        return None
    try:
        return re.compile(pattern, re.IGNORECASE)
    except re.error:
        return None


def normalize_domain(value: str) -> str:
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    if not text:
        return ""
    if "://" in text:
        text = urllib.parse.urlparse(text).hostname or ""
    else:
        text = text.split("/", 1)[0]
        if text.startswith("[") and "]" in text:
            text = text[1:text.index("]")]
        elif text.count(":") == 1:
            text = text.split(":", 1)[0]
    if text.startswith("*."):
        text = text[2:]
    return text.rstrip(".")


def load_geo_data(directory: Path | None = None) -> GeoData:
    global _cache_key, _cache_value
    folder = Path(directory) if directory is not None else geo_directory()
    geoip_path = folder / "geoip.dat"
    geosite_path = folder / "geosite.dat"
    if not geoip_path.is_file() or not geosite_path.is_file():
        raise FileNotFoundError(
            f"geoip.dat or geosite.dat is missing from {folder}; run scripts/fetch_geo.py"
        )
    geoip_stat = geoip_path.stat()
    geosite_stat = geosite_path.stat()
    key = (
        str(folder.resolve()),
        geoip_stat.st_mtime_ns,
        geoip_stat.st_size,
        geosite_stat.st_mtime_ns,
        geosite_stat.st_size,
    )
    if _cache_key == key and _cache_value is not None:
        return _cache_value
    data = GeoData(geoip_path.read_bytes(), geosite_path.read_bytes())
    _cache_key = key
    _cache_value = data
    logger.info("cyber geo datasets loaded from %s", folder)
    return data


def _text_field(record: dict, key: str) -> str | None:
    value = record.get(key)
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def _annotate(datasets: GeoData, observations: list) -> tuple[list[dict], int, int]:
    annotations = []
    address_count = 0
    domain_count = 0
    for record in observations or []:
        if not isinstance(record, dict):
            continue
        addresses = []
        domains = []
        for key in IP_FIELDS:
            text = _text_field(record, key)
            if text is None:
                continue
            addresses.append({"field": key, "value": text, "country": datasets.lookup_ip(text)})
        for key in DOMAIN_FIELDS:
            text = _text_field(record, key)
            if text is None:
                continue
            domains.append(
                {
                    "field": key,
                    "value": text,
                    "normalized": normalize_domain(text),
                    "categories": datasets.lookup_domain(text),
                }
            )
        if not addresses and not domains:
            continue
        address_count += len(addresses)
        domain_count += len(domains)
        item = {"addresses": addresses, "domains": domains}
        detection_id = _text_field(record, "detection_id")
        if detection_id:
            item["detection_id"] = detection_id
        annotations.append(item)
    return annotations, address_count, domain_count


def apply_geo_hook(picture: dict, observations: list | None, datasets: GeoData | None = None) -> dict:
    """Attach advisory geo labels when the env flag is on.

    With the flag off, the picture object is returned unchanged.
    """
    if not geo_enabled():
        return picture
    if not isinstance(picture, dict):
        return picture
    base = {"enabled": True, "policy": GEO_POLICY, "annotations": []}
    try:
        data = datasets if datasets is not None else load_geo_data()
    except (OSError, ValueError) as exc:
        logger.error("cyber geo datasets unavailable: %s", exc)
        picture["geo"] = {**base, "error": str(exc)}
        return picture
    annotations, address_count, domain_count = _annotate(data, observations or [])
    picture["geo"] = {**base, "annotations": annotations}
    logger.info(
        "cyber geo annotated %d address(es) and %d domain(s)",
        address_count,
        domain_count,
    )
    return picture
