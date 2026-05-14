"""
cve_tool — CVE lookup via the NVD API v2.

Replaces the 6-entry hardcoded dict in modules/network_module.py with a live
query against the National Vulnerability Database.

Rate limits (NVD):
  - Without API key: 5 requests per 30 seconds
  - With API key:    50 requests per 30 seconds

Set NVD_API_KEY environment variable to use authenticated mode.
"""
import os
import logging
from datetime import datetime

import httpx

logger = logging.getLogger(__name__)

_NVD_BASE      = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_TIMEOUT       = 20
_MAX_RESULTS   = 10   # cap results returned to LLM


def search_cve(product: str, version: str = "") -> dict:
    """Search the NVD for CVEs affecting a product/version."""
    keyword = f"{product} {version}".strip()
    if not keyword:
        return {"error": "product is required"}

    params = {
        "keywordSearch": keyword,
        "resultsPerPage": _MAX_RESULTS,
    }

    headers = {"Accept": "application/json"}
    api_key = os.environ.get("NVD_API_KEY", "")
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = httpx.get(_NVD_BASE, params=params, headers=headers, timeout=_TIMEOUT)
    except httpx.TimeoutException:
        return {"error": f"NVD API timed out after {_TIMEOUT}s", "product": product}
    except httpx.RequestError as e:
        return {"error": f"NVD API request failed: {e}", "product": product}

    if resp.status_code == 403:
        return {"error": "NVD API rate limit hit. Set NVD_API_KEY env var for higher limits."}
    if resp.status_code != 200:
        return {"error": f"NVD API returned HTTP {resp.status_code}", "product": product}

    try:
        data = resp.json()
    except Exception:
        return {"error": "NVD API returned non-JSON response", "product": product}

    total = data.get("totalResults", 0)
    items = data.get("vulnerabilities", [])
    cves  = [_parse_cve(item) for item in items if "cve" in item]

    return {
        "product":       product,
        "version":       version,
        "keyword":       keyword,
        "total_matches": total,
        "returned":      len(cves),
        "cves":          cves,
        "error":         None,
    }


def _parse_cve(item: dict) -> dict:
    cve  = item["cve"]
    cve_id = cve.get("id", "")

    # Description (prefer English)
    descriptions = cve.get("descriptions", [])
    description  = next(
        (d["value"] for d in descriptions if d.get("lang") == "en"),
        descriptions[0]["value"] if descriptions else "",
    )

    # CVSS score — try v3.1, then v3.0, then v2
    metrics  = cve.get("metrics", {})
    score    = None
    severity = None
    vector   = None

    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics and metrics[key]:
            m        = metrics[key][0]
            cvss     = m.get("cvssData", {})
            score    = cvss.get("baseScore")
            severity = cvss.get("baseSeverity") or m.get("baseSeverity")
            vector   = cvss.get("vectorString")
            break

    # Published date
    published = cve.get("published", "")
    if published:
        try:
            published = datetime.fromisoformat(published.rstrip("Z")).strftime("%Y-%m-%d")
        except ValueError:
            pass

    # References
    refs = [r["url"] for r in cve.get("references", [])[:3]]

    return {
        "cve_id":      cve_id,
        "description": description[:500] + ("…" if len(description) > 500 else ""),
        "cvss_score":  score,
        "severity":    severity,
        "vector":      vector,
        "published":   published,
        "references":  refs,
    }


search_cve.__schema__ = {
    "name": "search_cve",
    "description": (
        "Search the National Vulnerability Database (NVD) for CVEs affecting a specific "
        "product and version. Use after banner grabbing or service fingerprinting to check "
        "whether the detected software version has known vulnerabilities."
    ),
    "parameters": {
        "type": "object",
        "properties": {
            "product": {
                "type": "string",
                "description": "Product name to search (e.g. 'Apache httpd', 'OpenSSH', 'nginx').",
            },
            "version": {
                "type": "string",
                "description": "Version string to narrow the search (e.g. '2.4.49'). Optional.",
            },
        },
        "required": ["product"],
    },
}
