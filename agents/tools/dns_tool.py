"""
dns_tool — DNS lookup tool for LLM-driven agents.

Uses dnspython when available; falls back to socket for A/AAAA records only.
Covers the DNS recon work previously hardcoded in modules/recon.py.
"""
import socket
import logging

logger = logging.getLogger(__name__)

_SUPPORTED_TYPES = {"A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "PTR"}

try:
    import dns.resolver
    import dns.reversename
    _HAS_DNSPYTHON = True
except ImportError:
    _HAS_DNSPYTHON = False
    logger.warning("[DNS] dnspython not installed — only A/AAAA lookups available via socket")


def dns_lookup(hostname: str, record_type: str = "A") -> dict:
    """Perform a DNS lookup and return records of the requested type."""
    record_type = record_type.upper()

    if record_type not in _SUPPORTED_TYPES:
        return {
            "error": f"Unsupported record type '{record_type}'. "
                     f"Supported: {sorted(_SUPPORTED_TYPES)}"
        }

    if _HAS_DNSPYTHON:
        return _lookup_dnspython(hostname, record_type)
    return _lookup_socket(hostname, record_type)


def _lookup_dnspython(hostname: str, record_type: str) -> dict:
    try:
        if record_type == "PTR":
            rev = dns.reversename.from_address(hostname)
            answers = dns.resolver.resolve(rev, "PTR")
        else:
            answers = dns.resolver.resolve(hostname, record_type)

        records = []
        for rdata in answers:
            records.append(str(rdata))

        return {
            "hostname":    hostname,
            "record_type": record_type,
            "records":     records,
            "count":       len(records),
            "error":       None,
        }

    except dns.resolver.NXDOMAIN:
        return {"hostname": hostname, "record_type": record_type,
                "records": [], "count": 0, "error": "NXDOMAIN — host does not exist"}
    except dns.resolver.NoAnswer:
        return {"hostname": hostname, "record_type": record_type,
                "records": [], "count": 0, "error": f"No {record_type} records found"}
    except dns.resolver.Timeout:
        return {"hostname": hostname, "record_type": record_type,
                "records": [], "count": 0, "error": "DNS query timed out"}
    except Exception as e:
        logger.error(f"[DNS] dnspython error for {hostname}/{record_type}: {e}")
        return {"hostname": hostname, "record_type": record_type,
                "records": [], "count": 0, "error": str(e)}


def _lookup_socket(hostname: str, record_type: str) -> dict:
    if record_type not in ("A", "AAAA"):
        return {
            "hostname": hostname, "record_type": record_type,
            "records": [], "count": 0,
            "error": f"Socket fallback only supports A/AAAA. Install dnspython for {record_type}.",
        }
    family = socket.AF_INET6 if record_type == "AAAA" else socket.AF_INET
    try:
        results = socket.getaddrinfo(hostname, None, family)
        records = list({r[4][0] for r in results})
        return {
            "hostname":    hostname,
            "record_type": record_type,
            "records":     records,
            "count":       len(records),
            "error":       None,
        }
    except socket.gaierror as e:
        return {"hostname": hostname, "record_type": record_type,
                "records": [], "count": 0, "error": str(e)}


dns_lookup.__schema__ = {
    "name": "dns_lookup",
    "description": (
        "Perform a DNS lookup for a hostname and return records of the requested type. "
        "Useful for recon: resolving IPs, finding mail servers, nameservers, SPF/DKIM "
        "records in TXT, and checking for zone transfer indicators via NS/SOA."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "hostname": {
                "type": "string",
                "description": "Hostname or IP (for PTR lookups) to query.",
            },
            "record_type": {
                "type": "string",
                "enum": sorted(_SUPPORTED_TYPES),
                "description": "DNS record type to query (default: A).",
                "default": "A",
            },
        },
        "required": ["hostname"],
    },
}
