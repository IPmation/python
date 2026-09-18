"""Basic integration tests for the ipmation package.

These tests require network access to ipinfo.io, rdap.org, and
Cloudflare DNS-over-HTTPS.
"""

import pytest

from ipmation import lookup_ip, lookup_whois, lookup_dns


def test_lookup_ip_returns_structured_data():
    """lookup_ip should return geolocation and network fields."""
    info = lookup_ip("8.8.8.8")
    assert info.ip == "8.8.8.8"
    assert info.country
    assert info.asn
    assert info.isp


def test_lookup_whois_returns_registrar():
    """lookup_whois should return a registrar for well-known domains."""
    record = lookup_whois("example.com")
    assert record.domain.lower() == "example.com"
    assert record.registrar


def test_lookup_dns_returns_records():
    """lookup_dns should return a non-empty list for a valid A record."""
    answers = lookup_dns("example.com", "A")
    assert isinstance(answers, list)
    assert len(answers) > 0


def test_lookup_dns_rejects_unknown_record_type():
    """lookup_dns should raise ValueError for unsupported record types."""
    with pytest.raises(ValueError, match="Unsupported record type"):
        lookup_dns("example.com", "INVALID")