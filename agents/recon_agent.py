"""
ReconAgent — LLM-driven reconnaissance agent.

Replaces modules/recon.py. The LLM decides what DNS records to query,
what HTTP headers to inspect, and what TLS issues to investigate.
Python executes each tool call and feeds observations back.

Returns a dict compatible with the orchestrator and enrichment pipeline.
"""
import logging
from datetime import datetime
from urllib.parse import urlparse

from agents.base_agent import BaseAgent
from agents.tool_registry import build_registry
from agents.tools.dns_tool import dns_lookup
from agents.tools.ssl_tool import ssl_check
from agents.tools.http_tool import http_request
from agents.tools.finding_tool import report_finding

logger = logging.getLogger(__name__)

# ── System prompt ──────────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """You are a security reconnaissance agent. Your job is to investigate a target and identify security weaknesses through careful observation.

INVESTIGATION ORDER — work through each area in sequence:

1. DNS RESOLUTION
   - dns_lookup(hostname, "A") — resolve IP address
   - dns_lookup(hostname, "NS") — identify nameservers
   - dns_lookup(hostname, "MX") — check if mail is handled (enables email security checks)
   - dns_lookup(hostname, "TXT") — look for SPF, DMARC records
   - dns_lookup(hostname, "CNAME") — check for dangling CNAME or CDN delegation

2. TLS / SSL INSPECTION
   - ssl_check(host) — check certificate validity, expiry, SANs, and protocol support
   - Report if: TLS 1.0 or 1.1 is supported, cert is expired, cert has < 30 days left,
     cert validation fails, self-signed cert detected

3. HTTP HEADER ANALYSIS
   - http_request("GET", url) — grab the base response
   - http_request("GET", url + "/nonexistent") — check error page information disclosure
   - Check response headers for presence/absence of security controls:
       strict-transport-security, content-security-policy, x-frame-options,
       x-content-type-options, referrer-policy, permissions-policy
   - Check if Server or X-Powered-By headers disclose version strings
   - Check if HTTP (not HTTPS) is accessible and whether it redirects

4. EMAIL SECURITY (only if MX records were found)
   - Evaluate TXT records for SPF policy strength (check for ~all vs -all vs missing)
   - Check for DMARC record at _dmarc.<hostname>: dns_lookup("_dmarc."+hostname, "TXT")
   - Check for DKIM: dns_lookup("default._domainkey."+hostname, "TXT")
   - Report missing or permissive policies

FINDING TYPES — always include `type` in your report_finding() call:
  missing_security_header — HTTP security header absent from response
  ssl_error               — TLS/cert problem
  information_disclosure  — server version or internal detail leaked
  web_vulnerability       — open redirect, CORS misconfiguration, etc.

SEVERITY GUIDELINES:
  High:   Expired/invalid cert, certificate validation failure
  Medium: TLS 1.0/1.1 supported, missing HSTS, missing CSP, HTTP accessible without redirect,
          missing SPF, missing DMARC, DMARC policy is "none"
  Low:    Missing X-Frame-Options, missing X-Content-Type-Options, missing Referrer-Policy,
          SPF uses ~all (softfail) instead of -all
  Info:   Server/technology version disclosure in headers

EVIDENCE REQUIREMENTS — every report_finding() call must include in evidence:
  url          — the affected URL or endpoint
  curl_poc     — exact curl command to reproduce
  observation  — what you saw (relevant headers, cert details, DNS record value)

CALL report_finding() only for confirmed issues — things you actually observed in tool results, not suspicions.
When you have investigated all four areas above, call done.
"""

# ── Agent class ────────────────────────────────────────────────────────────────

class ReconAgent:
    """
    LLM-driven recon agent. Drop-in replacement for modules/recon.run_recon().
    Returns a dict compatible with orchestrator and enrichment pipeline.
    """

    def __init__(self, llm, scope: str = None):
        self.llm   = llm
        self.scope = scope

    def run(self, target: str, config=None) -> dict:
        hostname, scheme = _parse_target(target)
        scope            = self.scope or hostname

        registry = build_registry(dns_lookup, ssl_check, http_request, report_finding)
        agent    = BaseAgent(
            llm            = self.llm,
            tool_registry  = registry,
            system_prompt  = _SYSTEM_PROMPT,
            max_iterations = 40,
            scope          = scope,
        )

        goal = (
            f"Perform security reconnaissance on: {target}\n"
            f"Hostname: {hostname} | Scheme: {scheme} | "
            f"Auth: {config.build_auth_summary() if config else 'Unauthenticated'}"
        )

        start  = datetime.utcnow()
        result = agent.run(goal=goal, context={"target": target, "hostname": hostname})
        elapsed = (datetime.utcnow() - start).total_seconds()

        context = _extract_context(target, hostname, scheme, result.log)

        logger.info(
            f"[RECON_AGENT] Done — {result.iterations} iterations, "
            f"{result.tool_call_count} tool calls, "
            f"{len(result.findings)} findings, "
            f"status={result.status}"
        )

        return {
            "module":             "recon",
            "target":             target,
            "hostname":           hostname,
            "ip_address":         context.get("ip_address"),
            "scheme":             context.get("scheme", scheme),
            "host_type":          context.get("host_type", "unknown"),
            "open_ports":         context.get("open_ports", []),
            "http_info":          context.get("http_info", {}),
            "technologies":       context.get("technologies", []),
            "findings":           _normalise_findings(result.findings, target),
            "tool_used":          "ai_recon_agent",
            "auth_used":          config.build_auth_summary() if config else "Unauthenticated",
            "scan_time":          elapsed,
            "agent_status":       result.status,
            "agent_iterations":   result.iterations,
            "agent_summary":      result.summary,
        }


# ── Context extraction ─────────────────────────────────────────────────────────

def _extract_context(target: str, hostname: str, scheme: str, log: list) -> dict:
    """
    Parse agent log entries to reconstruct the structured recon context
    that the orchestrator uses for domain inference and reporting.
    """
    ctx = {
        "ip_address":  None,
        "scheme":      scheme,
        "host_type":   "unknown",
        "open_ports":  [],
        "http_info":   {},
        "technologies":[],
    }

    http_responded = False
    web_ports      = {80, 443, 8080, 8443, 8000, 8888}

    for entry in log:
        tool        = entry.get("tool", "")
        args        = entry.get("args", {})
        observation = entry.get("observation", "")

        # Try to parse observation as dict if it's a JSON string
        obs = _safe_parse(observation)

        if tool == "dns_lookup" and args.get("record_type", "A") == "A":
            records = obs.get("records", []) if isinstance(obs, dict) else []
            if records:
                ctx["ip_address"] = records[0]

        if tool == "http_request" and isinstance(obs, dict) and obs.get("status_code"):
            http_responded = True
            status = obs.get("status_code", 0)
            final_url = obs.get("final_url", target)
            resp_headers = obs.get("headers", {})
            ctx["http_info"] = {
                "status_code":           status,
                "headers":               resp_headers,
                "server":                resp_headers.get("server", ""),
                "https":                 final_url.startswith("https"),
                "redirect_url":          final_url if final_url != target else None,
                "raw_response_headers":  "\n".join(f"{k}: {v}" for k, v in resp_headers.items()),
                "raw_request":           f'curl -sk -i "{target}"',
            }
            ctx["scheme"] = "https" if final_url.startswith("https") else "http"
            ctx["technologies"] = _detect_technologies(resp_headers)

        if tool == "ssl_check" and isinstance(obs, dict) and not obs.get("error"):
            # Confirm HTTPS port is reachable
            http_responded = True

    # Host type inference
    if http_responded:
        ctx["host_type"] = "web_application"
    elif ctx["ip_address"]:
        ctx["host_type"] = "network_host"

    return ctx


def _detect_technologies(headers: dict) -> list:
    techs   = []
    headers = {k.lower(): v for k, v in headers.items()}
    server  = headers.get("server", "").lower()
    for key, name in [("nginx","Nginx"), ("apache","Apache"), ("iis","Microsoft IIS"),
                      ("cloudflare","Cloudflare"), ("gunicorn","Gunicorn"),
                      ("caddy","Caddy"), ("lighttpd","Lighttpd")]:
        if key in server:
            techs.append(name)
    if "x-powered-by" in headers:
        techs.append(headers["x-powered-by"])
    if "x-generator" in headers:
        techs.append(headers["x-generator"])
    return list(dict.fromkeys(techs))


# ── Finding normalisation ──────────────────────────────────────────────────────

def _normalise_findings(findings: list, target: str) -> list:
    """
    Convert report_finding() output format to the format enrichment.py expects.

    report_finding uses:  severity, remediation, cwe_id, references
    enrichment expects:   risk,     solution,    cwe,    cve
    """
    normalised = []
    for f in findings:
        finding = dict(f)

        # Field renames
        if "remediation" in finding:
            finding["solution"] = finding.pop("remediation")
        if "severity" in finding:
            finding["risk"] = finding.pop("severity")
        if "cwe_id" in finding:
            finding["cwe"] = finding.pop("cwe_id")

        # Extract CVE from references if present
        refs = finding.pop("references", []) or []
        for ref in refs:
            if "CVE-" in ref.upper():
                import re
                m = re.search(r"CVE-\d{4}-\d+", ref, re.IGNORECASE)
                if m:
                    finding["cve"] = m.group().upper()
                    break

        # Ensure url is set — pull from evidence if not provided
        if not finding.get("url"):
            evidence = finding.get("evidence") or {}
            finding["url"] = evidence.get("url") or target

        # Default type if LLM omitted it
        if not finding.get("type"):
            finding["type"] = _infer_type(finding.get("name", ""))

        normalised.append(finding)
    return normalised


def _infer_type(name: str) -> str:
    name_lower = name.lower()
    if any(k in name_lower for k in ("header", "csp", "hsts", "frame", "sniff", "referrer")):
        return "missing_security_header"
    if any(k in name_lower for k in ("tls", "ssl", "cert", "https", "cipher")):
        return "ssl_error"
    if any(k in name_lower for k in ("version", "banner", "disclosure", "leak", "expose")):
        return "information_disclosure"
    if any(k in name_lower for k in ("spf", "dmarc", "dkim", "email")):
        return "missing_security_header"
    return "web_vulnerability"


# ── Helpers ────────────────────────────────────────────────────────────────────

def _parse_target(target: str) -> tuple:
    if target.startswith("http://") or target.startswith("https://"):
        parsed = urlparse(target)
        return parsed.hostname or target, parsed.scheme
    return target, "https"


def _safe_parse(value) -> dict:
    """Try to parse a value as a dict — return {} on failure."""
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        import json
        try:
            parsed = json.loads(value)
            if isinstance(parsed, dict):
                return parsed
        except (json.JSONDecodeError, ValueError):
            pass
    return {}
