"""
ssl_tool — TLS/SSL inspection tool for LLM-driven agents.

Checks:
  - Certificate validity, expiry, subject, SANs, issuer
  - Protocol version support (TLS 1.0, 1.1, 1.2, 1.3)
  - Weak protocol detection (TLS 1.0/1.1 flagged as findings)

Replaces probe_weak_tls from modules/probes.py with a proper tool that
returns structured data the LLM can reason about.
"""
import ssl
import socket
import datetime
import logging

logger = logging.getLogger(__name__)

_CONNECT_TIMEOUT = 10

# TLS versions to probe, in ascending order
_TLS_VERSIONS = [
    ("TLS 1.0", "TLSv1",   True),   # (label, attr_name, is_weak)
    ("TLS 1.1", "TLSv1_1", True),
    ("TLS 1.2", "TLSv1_2", False),
    ("TLS 1.3", "TLSv1_3", False),
]


def ssl_check(host: str, port: int = 443) -> dict:
    """Inspect TLS configuration and certificate for a host:port."""
    result = {
        "host":                  host,
        "port":                  port,
        "certificate":           None,
        "protocol_support":      {},
        "weak_protocols":        [],
        "cert_error":            None,
        "error":                 None,
    }

    # ── Certificate inspection ─────────────────────────────────────────────────
    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = True
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                cert      = ssock.getpeercert()
                proto     = ssock.version()
                cipher    = ssock.cipher()

        result["certificate"]      = _parse_cert(cert)
        result["negotiated_proto"] = proto
        result["negotiated_cipher"]= cipher[0] if cipher else None

    except ssl.SSLCertVerificationError as e:
        result["cert_error"] = str(e)
        # Still continue to check protocol support
    except ssl.SSLError as e:
        result["cert_error"] = str(e)
    except (socket.timeout, ConnectionRefusedError, OSError) as e:
        result["error"] = f"Connection failed: {e}"
        return result

    # ── Protocol version probing ───────────────────────────────────────────────
    for label, attr, is_weak in _TLS_VERSIONS:
        supported = _probe_tls_version(host, port, attr)
        result["protocol_support"][label] = supported
        if supported and is_weak:
            result["weak_protocols"].append(label)

    return result


def _probe_tls_version(host: str, port: int, version_attr: str) -> bool:
    """Attempt a TLS handshake forcing a specific protocol version."""
    tls_version = getattr(ssl.TLSVersion, version_attr, None)
    if tls_version is None:
        return False   # Python build doesn't expose this constant

    try:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.minimum_version  = tls_version
        ctx.maximum_version  = tls_version
        ctx.check_hostname   = False
        ctx.verify_mode      = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=_CONNECT_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except (ssl.SSLError, OSError):
        return False


def _parse_cert(cert: dict) -> dict:
    """Extract the fields an analyst cares about from a peercert dict."""
    if not cert:
        return {}

    # Subject
    subject = {}
    for pair in cert.get("subject", ()):
        for k, v in pair:
            subject[k] = v

    # SANs
    sans = [v for t, v in cert.get("subjectAltName", ()) if t == "DNS"]

    # Expiry
    not_after  = cert.get("notAfter", "")
    not_before = cert.get("notBefore", "")
    expiry     = None
    days_left  = None
    expired    = None
    if not_after:
        try:
            dt        = datetime.datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            expiry    = dt.isoformat()
            days_left = (dt - datetime.datetime.utcnow()).days
            expired   = days_left < 0
        except ValueError:
            expiry = not_after

    # Issuer
    issuer = {}
    for pair in cert.get("issuer", ()):
        for k, v in pair:
            issuer[k] = v

    return {
        "subject":    subject,
        "issuer":     issuer,
        "sans":       sans,
        "not_before": not_before,
        "not_after":  not_after,
        "expiry_iso": expiry,
        "days_left":  days_left,
        "expired":    expired,
        "serial":     cert.get("serialNumber"),
        "version":    cert.get("version"),
    }


ssl_check.__schema__ = {
    "name": "ssl_check",
    "description": (
        "Inspect the TLS configuration of a host: certificate details (subject, SANs, "
        "expiry, issuer), supported protocol versions (TLS 1.0–1.3), and negotiated "
        "cipher. Flags weak protocols (TLS 1.0, TLS 1.1) that should be disabled."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "host": {
                "type": "string",
                "description": "Hostname to check (without scheme or port).",
            },
            "port": {
                "type": "integer",
                "description": "TLS port (default: 443).",
                "default": 443,
            },
        },
        "required": ["host"],
    },
}
