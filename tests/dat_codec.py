"""Minimal protobuf encoder for synthetic GeoIPList and GeoSiteList fixtures."""

from __future__ import annotations

import ipaddress


def varint(value: int) -> bytes:
    if value < 0:
        raise ValueError("varint must be non-negative")
    out = bytearray()
    while True:
        piece = value & 0x7F
        value >>= 7
        if value:
            out.append(piece | 0x80)
        else:
            out.append(piece)
            return bytes(out)


def key(field: int, wire: int) -> bytes:
    return varint((field << 3) | wire)


def length_field(field: int, payload: bytes) -> bytes:
    return key(field, 2) + varint(len(payload)) + payload


def varint_field(field: int, value: int) -> bytes:
    return key(field, 0) + varint(value)


def encode_cidr(network: str) -> bytes:
    parsed = ipaddress.ip_network(network, strict=False)
    body = length_field(1, parsed.network_address.packed)
    if parsed.prefixlen:
        body += varint_field(2, parsed.prefixlen)
    return body


def encode_geoip_list(entries: list[tuple[str, list[str], bool]]) -> bytes:
    """entries are (country_code, cidr strings, inverse_match)."""
    out = b""
    for code, cidrs, inverse in entries:
        body = length_field(1, code.encode("utf-8"))
        for cidr in cidrs:
            body += length_field(2, encode_cidr(cidr))
        if inverse:
            body += varint_field(3, 1)
        out += length_field(1, body)
    return out


def encode_domain(kind: int, value: str) -> bytes:
    body = b""
    if kind:
        body += varint_field(1, kind)
    body += length_field(2, value.encode("utf-8"))
    return body


def encode_geosite_list(entries: list[tuple[str, list[tuple[int, str]]]]) -> bytes:
    """entries are (category, [(domain type, value), ...])."""
    out = b""
    for code, domains in entries:
        body = length_field(1, code.encode("utf-8"))
        for kind, value in domains:
            body += length_field(2, encode_domain(kind, value))
        out += length_field(1, body)
    return out


PLAIN = 0
REGEX = 1
ROOT_DOMAIN = 2
FULL = 3


def synthetic_geoip() -> bytes:
    return encode_geoip_list(
        [
            ("US", ["8.8.8.0/24", "1.2.0.0/16", "2001:db8:1::/48"], False),
            ("CA", ["1.2.3.0/24"], False),
            ("PRIVATE", ["10.0.0.0/8"], False),
            ("TESTNET", ["192.0.2.0/24"], True),
        ]
    )


def synthetic_geosite() -> bytes:
    return encode_geosite_list(
        [
            ("GOOGLE", [(ROOT_DOMAIN, "google.com"), (FULL, "dns.google")]),
            ("ADS", [(PLAIN, "doubleclick")]),
            ("NEWS", [(REGEX, r"\.news$")]),
            ("CN", [(ROOT_DOMAIN, "example.cn")]),
        ]
    )
