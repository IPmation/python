"""Core lookup functions.

All queries are forwarded to public APIs and results are normalized into
the data models defined in :mod:`ipmation.models`.
"""

import httpx
from typing import List, Optional, Tuple

from .models import IPInfo, WhoisInfo


_IPINFO_BASE = "https://ipinfo.io"
_RDAP_BASE = "https://rdap.org"
_DOH_ENDPOINT = "https://cloudflare-dns.com/dns-query"

_REQUEST_TIMEOUT = 10.0

_DNS_RECORD_TYPES = {
    "A": 1,
    "NS": 2,
    "CNAME": 5,
    "MX": 15,
    "TXT": 16,
    "AAAA": 28,
}


def _parse_org(org: str) -> Tuple[Optional[str], Optional[str]]:
    """Split an ipinfo.io `org` field into (ASN, ISP) components.

    The field is typically formatted as "AS12345 Provider Name".
    """
    if not org:
        return None, None
    parts = org.split(" ", 1)
    if len(parts) == 2 and parts[0].upper().startswith("AS"):
        return parts[0], parts[1]
    return None, org


def _normalize_domain(domain: str) -> str:
    """Strip protocol prefixes, ``www.``, and subpaths from a domain."""
    domain = domain.strip().lower()
    for prefix in ("https://", "http://", "www."):
        if domain.startswith(prefix):
            domain = domain[len(prefix):]
    return domain.split("/")[0]


def _extract_registrar(entities: list) -> Optional[str]:
    """Extract the registrar organization name from RDAP entities."""
    for entity in entities:
        if "registrar" in entity.get("roles", []):
            vcard = entity.get("vcardArray")
            if vcard and len(vcard) > 1:
                for item in vcard[1]:
                    if item[0] == "fn":
                        return item[3]
    return None


def _extract_event_date(events: list, action: str) -> Optional[str]:
    """Extract a date from RDAP events by action name."""
    for event in events:
        if event.get("eventAction") == action:
            date = event.get("eventDate", "")
            return date[:10] if date else None
    return None


def _extract_nameservers(nameservers: list) -> List[str]:
    """Extract lowercase name server hostnames from RDAP data."""
    return [ns.get("ldhName", "").lower() for ns in nameservers]


def _extract_dnssec(secure_dns: dict) -> str:
    """Return DNSSEC status as a human-readable string."""
    return "Signed" if secure_dns.get("delegationSigned") else "Unsigned"


def lookup_ip(ip: str = "") -> IPInfo:
    """Look up IP address information.

    Args:
        ip: The IPv4 or IPv6 address to query. If empty, the caller's
            public IP address is resolved.

    Returns:
        An IPInfo instance containing geolocation, ISP, ASN, and
        timezone data.

    Raises:
        ValueError: If the API returns an error response.
        httpx.HTTPError: If the request fails.
    """
    url = f"{_IPINFO_BASE}/{ip}/json" if ip else f"{_IPINFO_BASE}/json"

    with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
        response = client.get(url)
        response.raise_for_status()
        data = response.json()

    if "error" in data:
        message = data["error"].get("message", "unknown error")
        raise ValueError(f"IP lookup failed: {message}")

    asn, isp = _parse_org(data.get("org", ""))

    return IPInfo(
        ip=data.get("ip", "Unknown"),
        city=data.get("city"),
        region=data.get("region"),
        country=data.get("country"),
        postal=data.get("postal"),
        timezone=data.get("timezone"),
        loc=data.get("loc"),
        isp=isp,
        asn=asn,
        raw=data,
    )


def lookup_whois(domain: str) -> WhoisInfo:
    """Look up domain registration data via RDAP.

    Args:
        domain: The domain name to query. Protocol prefixes and
            subpaths are stripped automatically.

    Returns:
        A WhoisInfo instance containing registrar, status, dates, name
        servers, and DNSSEC information.

    Raises:
        ValueError: If the domain is not found, the registry does not
            support RDAP, or the API returns an error.
        httpx.HTTPError: If the request fails.
    """
    domain = _normalize_domain(domain)

    with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
        response = client.get(
            f"{_RDAP_BASE}/domain/{domain}",
            headers={"Accept": "application/rdap+json, application/json"},
        )
        if response.status_code == 404:
            raise ValueError(
                "Domain not found, or its registry does not support RDAP."
            )
        response.raise_for_status()
        data = response.json()

    if data.get("errorCode"):
        raise ValueError(
            data.get("title") or data.get("description") or "Lookup failed."
        )

    return WhoisInfo(
        domain=data.get("ldhName") or data.get("unicodeName") or "Unknown",
        registrar=_extract_registrar(data.get("entities", [])),
        status=data.get("status", []),
        created=_extract_event_date(data.get("events", []), "registration"),
        updated=_extract_event_date(data.get("events", []), "last changed"),
        expires=_extract_event_date(data.get("events", []), "expiration"),
        nameservers=_extract_nameservers(data.get("nameservers", [])),
        dnssec=_extract_dnssec(data.get("secureDNS", {})),
        raw=data,
    )


def lookup_dns(domain: str, record_type: str = "A") -> List[str]:
    """Query DNS records for a domain.

    Args:
        domain: The domain name to query.
        record_type: The DNS record type. One of ``A``, ``AAAA``,
            ``CNAME``, ``MX``, ``TXT``, or ``NS``. Defaults to ``A``.

    Returns:
        A list of record values as strings.

    Raises:
        ValueError: If the record type is unsupported, the domain does
            not exist, or the DoH endpoint returns a non-zero status.
        httpx.HTTPError: If the request fails.
    """
    record_type = record_type.upper()
    if record_type not in _DNS_RECORD_TYPES:
        raise ValueError(f"Unsupported record type: {record_type}")

    with httpx.Client(timeout=_REQUEST_TIMEOUT) as client:
        response = client.get(
            _DOH_ENDPOINT,
            params={"name": domain, "type": record_type},
            headers={"Accept": "application/dns-json"},
        )
        response.raise_for_status()
        data = response.json()

    status = data.get("Status")
    if status == 3:
        raise ValueError("Domain does not exist.")
    if status != 0:
        raise ValueError(f"DNS query returned status {status}.")

    return [answer.get("data", "") for answer in data.get("Answer", [])]