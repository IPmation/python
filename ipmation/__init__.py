"""IPmation — a Python library for IP, WHOIS, and DNS lookups."""

from .core import lookup_ip, lookup_whois, lookup_dns
from .models import IPInfo, WhoisInfo

__version__ = "0.1.0"
__all__ = ["lookup_ip", "lookup_whois", "lookup_dns", "IPInfo", "WhoisInfo"]