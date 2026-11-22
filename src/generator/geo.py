"""Synthetic GeoIP / ASN registry.

CloudTrail records carry only an IP, so geo/ASN has to come from a lookup, exactly as it would with
DB-IP Lite in production. This registry is fully synthetic (each /8 or half-/8 is assigned to a made-up
network), so the project needs no downloads. The detector calls `lookup()` the same way it would call a
real GeoIP database; swapping in DB-IP Lite later only means replacing this one function.
"""
from __future__ import annotations

import math
import random
from dataclasses import dataclass
from functools import lru_cache

# kind: residential | office | aws | hosting | vpn
# (first_octet, second_lo, second_hi, country, asn, org, kind)
NETWORKS: list[tuple[int, int, int, str, str, str, str]] = [
    (11, 0, 127, "US", "AS7922", "Comcast Cable", "residential"),
    (11, 128, 255, "US", "AS701", "Verizon Fios", "residential"),
    (13, 0, 63, "US", "AS64500", "Acme Corp Office", "office"),
    (13, 64, 127, "US", "AS64501", "Acme CI Egress (NAT)", "aws"),
    (52, 0, 255, "US", "AS16509", "Amazon AWS", "aws"),
    (45, 0, 255, "US", "AS14061", "Cheap VPS Hosting", "hosting"),
    (81, 0, 255, "GB", "AS2856", "BT Broadband", "residential"),
    (85, 0, 255, "DE", "AS3320", "Deutsche Telekom", "residential"),
    (103, 0, 255, "IN", "AS55836", "Reliance Jio", "residential"),
    (99, 0, 255, "CA", "AS577", "Bell Canada", "residential"),
    (95, 0, 255, "RU", "AS12389", "Rostelecom", "residential"),
    (193, 0, 255, "RU", "AS49505", "Selectel Hosting", "hosting"),
    (111, 0, 255, "CN", "AS4134", "ChinaNet", "residential"),
    (105, 0, 255, "NG", "AS29465", "MTN Nigeria", "residential"),
    (177, 0, 255, "BR", "AS28573", "Claro Brasil", "residential"),
    (188, 0, 255, "NL", "AS60781", "Offshore Hosting BV", "hosting"),
    (185, 0, 255, "NL", "AS9009", "Anonymous VPN Provider", "vpn"),
    (139, 0, 255, "SG", "AS132203", "SG Cloud VPS", "hosting"),
    (118, 0, 255, "AU", "AS1221", "Telstra", "residential"),
]

COUNTRIES: dict[str, tuple[str, float, float]] = {  # code -> (name, lat, lon)
    "US": ("United States", 40.7, -74.0),
    "GB": ("United Kingdom", 51.5, -0.1),
    "DE": ("Germany", 52.5, 13.4),
    "IN": ("India", 19.1, 72.9),
    "CA": ("Canada", 43.7, -79.4),
    "RU": ("Russia", 55.8, 37.6),
    "CN": ("China", 31.2, 121.5),
    "NG": ("Nigeria", 6.5, 3.4),
    "BR": ("Brazil", -23.5, -46.6),
    "NL": ("Netherlands", 52.4, 4.9),
    "SG": ("Singapore", 1.35, 103.8),
    "AU": ("Australia", -33.9, 151.2),
}


@dataclass(frozen=True)
class Geo:
    country: str
    country_name: str
    lat: float
    lon: float
    asn: str
    org: str
    kind: str


_UNKNOWN = Geo("ZZ", "Unknown", 0.0, 0.0, "AS0", "Unknown", "unknown")


_ENABLED = True


def set_enabled(enabled: bool) -> None:
    """Turn the synthetic registry off for REAL data: its networks are made up, so geolocating real (or anonymized) IPs with it
    would invent countries and impossible-travel alerts. Disabled, every IP is 'unknown' and geo-based signals stay silent."""
    global _ENABLED
    _ENABLED = enabled


def lookup(ip: str) -> Geo:
    return _lookup(ip) if _ENABLED else _UNKNOWN


@lru_cache(maxsize=200_000)
def _lookup(ip: str) -> Geo:
    try:
        a, b, _, _ = (int(x) for x in ip.split("."))
    except ValueError:
        return _UNKNOWN  # service principals like "lambda.amazonaws.com"
    for o, lo, hi, cc, asn, org, kind in NETWORKS:
        if o == a and lo <= b <= hi:
            name, lat, lon = COUNTRIES[cc]
            return Geo(cc, name, lat, lon, asn, org, kind)
    return _UNKNOWN


def haversine_km(lat1: float, lon1: float, lat2: float, lon2: float) -> float:
    r = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dphi, dl = p2 - p1, math.radians(lon2 - lon1)
    h = math.sin(dphi / 2) ** 2 + math.cos(p1) * math.cos(p2) * math.sin(dl / 2) ** 2
    return 2 * r * math.asin(math.sqrt(h))


def distance_km(ip1: str, ip2: str) -> float:
    g1, g2 = lookup(ip1), lookup(ip2)
    return haversine_km(g1.lat, g1.lon, g2.lat, g2.lon)


def random_ip(rng: random.Random, country: str | None = None, kind: str | None = None, asn: str | None = None) -> str:
    cands = [n for n in NETWORKS if (country is None or n[3] == country) and (kind is None or n[6] == kind)
             and (asn is None or n[4] == asn)]
    if not cands:
        raise ValueError(f"no network for country={country} kind={kind}")
    o, lo, hi, *_ = rng.choice(cands)
    return f"{o}.{rng.randint(lo, hi)}.{rng.randint(0, 255)}.{rng.randint(1, 254)}"
