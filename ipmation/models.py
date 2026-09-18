"""Data models returned by the lookup functions."""

from dataclasses import dataclass, field
from typing import Optional, List


@dataclass
class IPInfo:
    """Structured result of an IP address lookup.

    Attributes:
        ip: The queried IP address.
        city: City name, if available.
        region: Region or state name, if available.
        country: ISO 3166-1 alpha-2 country code.
        postal: Postal code, if available.
        timezone: IANA timezone identifier.
        loc: Latitude and longitude, formatted as "lat,lon".
        isp: Internet service provider name.
        asn: Autonomous system number, prefixed with "AS".
        raw: The unmodified API response.
    """

    ip: str
    city: Optional[str] = None
    region: Optional[str] = None
    country: Optional[str] = None
    postal: Optional[str] = None
    timezone: Optional[str] = None
    loc: Optional[str] = None
    isp: Optional[str] = None
    asn: Optional[str] = None
    raw: dict = field(default_factory=dict)


@dataclass
class WhoisInfo:
    """Structured result of a domain WHOIS lookup.

    Attributes:
        domain: The queried domain name.
        registrar: Registrar organization name.
        status: List of RDAP status codes.
        created: Registration date in ISO 8601 format.
        updated: Last modification date in ISO 8601 format.
        expires: Expiration date in ISO 8601 format.
        nameservers: List of authoritative name servers.
        dnssec: Whether DNSSEC is signed ("Signed" or "Unsigned").
        raw: The unmodified API response.
    """

    domain: str
    registrar: Optional[str] = None
    status: List[str] = field(default_factory=list)
    created: Optional[str] = None
    updated: Optional[str] = None
    expires: Optional[str] = None
    nameservers: List[str] = field(default_factory=list)
    dnssec: Optional[str] = None
    raw: dict = field(default_factory=dict)