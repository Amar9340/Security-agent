"""
False Positive Detection Agent — Phase 3 (Enhanced)

Stage 1 — Multi-evidence correlation (pre-LLM, pure logic):
  Annotates every finding with tool_count, corroborated, and linked_findings.
  Adjusts confidence baseline before any LLM call.

Stage 2 — Direct re-verification (pre-LLM, concurrent HTTP):
  Re-requests the finding URL and verifies the condition for ZAP/Nuclei findings.
  Probe findings skip this step — they are already direct HTTP checks.
  Contradicted findings are auto-marked likely_false_positive and skip the LLM.

Stage 3 — LLM analysis (per-finding, Critical/High only):
  Same per-finding LLM call as before, now with two additional output fields:
  exploit_feasibility and feasibility_reason.
"""
import concurrent.futures
import logging
import re
import time

import httpx

from agents.llm_client import get_llm

_RATE_LIMITED_PROVIDERS = {"groq", "openrouter"}
_INTER_CALL_DELAY       = 2.0
_PROBE_TOOL             = "Built-in HTTP Probe"

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = """You are a security analyst. Classify findings and return JSON only."""


def analyse_findings(findings: list) -> list:
    """
    Run FP analysis on a list of enriched findings.

    Pipeline: Stage 1 (correlate) → Stage 2 (re-verify) → Stage 3 (LLM).
    Returns the findings list with FP fields added to each entry.
    """
    if not findings:
        return findings

    findings = _correlate_findings(findings)
    findings = _revalidate_all(findings)

    llm = get_llm()
    if not llm.is_available():
        logger.info("[FP-AGENT] LLM unavailable — using heuristic scores only")
        return findings

    # Critical/High only; skip findings already auto-marked by Stage 2
    priority_indices = [
        i for i, f in enumerate(findings)
        if f.get("severity") in ("Critical", "High")
        and f.get("fp_status") != "likely_false_positive"
    ]
    needs_delay = llm.provider in _RATE_LIMITED_PROVIDERS

    logger.info(
        f"[FP-AGENT] Analysing {len(priority_indices)} Critical/High findings with "
        f"{llm.model} (skipping {len(findings) - len(priority_indices)})"
    )

    for loop_i, idx in enumerate(priority_indices):
        try:
            findings[idx] = _analyse_single(llm, findings[idx])
        except Exception as e:
            logger.warning(f"[FP-AGENT] Failed on '{findings[idx].get('name')}': {e}")
        if needs_delay and loop_i < len(priority_indices) - 1:
            time.sleep(_INTER_CALL_DELAY)

    confirmed = sum(1 for f in findings if f.get("fp_status") == "confirmed")
    false_pos = sum(1 for f in findings if f.get("fp_status") == "likely_false_positive")
    uncertain = sum(1 for f in findings if f.get("fp_status") == "uncertain")
    logger.info(
        f"[FP-AGENT] Done — confirmed={confirmed} | "
        f"likely_fp={false_pos} | uncertain={uncertain}"
    )
    return findings


# ── Stage 1: Multi-evidence correlation ───────────────────────────────────────

def _normalise_name(name: str) -> str:
    return re.sub(r"\s+", " ", re.sub(r"[^\w\s]", "", name.lower())).strip()


def _correlate_findings(findings: list) -> list:
    """
    Annotate each finding with:
      tool_count      — distinct tools that reported this finding on this URL
      corroborated    — True if 2+ tools agree
      linked_findings — IDs of other findings on the same URL

    Confidence adjustments:
      corroborated     → +0.15
      single-tool only → -0.10
    """
    # Group by (normalised name, url) to detect multi-tool agreement
    groups: dict = {}
    for f in findings:
        key = (_normalise_name(f.get("name", "")), f.get("url", ""))
        groups.setdefault(key, []).append(f)

    # Group by url for linked_findings
    by_url: dict = {}
    for f in findings:
        by_url.setdefault(f.get("url", ""), []).append(f.get("id", ""))

    annotated = []
    for f in findings:
        key          = (_normalise_name(f.get("name", "")), f.get("url", ""))
        tools        = {g.get("tool_used", "unknown") for g in groups[key]}
        tool_count   = len(tools)
        corroborated = tool_count >= 2
        linked       = [fid for fid in by_url.get(f.get("url", ""), [])
                        if fid != f.get("id", "")]

        updated                   = dict(f)
        updated["tool_count"]     = tool_count
        updated["corroborated"]   = corroborated
        updated["linked_findings"] = linked

        base = _clamp(float(updated.get("confidence_score") or 0.5))
        updated["confidence_score"] = _clamp(base + (0.15 if corroborated else -0.10))

        annotated.append(updated)

    n_corroborated = sum(1 for f in annotated if f.get("corroborated"))
    logger.info(
        f"[FP-AGENT] Correlation: {n_corroborated}/{len(annotated)} findings corroborated"
    )
    return annotated


# ── Stage 2: Direct re-verification ───────────────────────────────────────────

def _revalidate_all(findings: list) -> list:
    """Re-verify ZAP/Nuclei findings concurrently. Probe findings are skipped."""
    check_indices = [
        i for i, f in enumerate(findings)
        if f.get("tool_used") != _PROBE_TOOL
    ]
    if not check_indices:
        return findings

    revalidated: dict = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        future_map = {
            ex.submit(_revalidate_finding, findings[i]): i
            for i in check_indices
        }
        for fut in concurrent.futures.as_completed(future_map):
            idx = future_map[fut]
            try:
                revalidated[idx] = fut.result()
            except Exception:
                revalidated[idx] = findings[idx]

    result = [revalidated[i] if i in revalidated else f
              for i, f in enumerate(findings)]

    contradicted = sum(1 for f in result if f.get("revalidation_status") == "contradicted")
    confirmed    = sum(1 for f in result if f.get("revalidation_status") == "confirmed")
    logger.info(
        f"[FP-AGENT] Re-validation: {confirmed} confirmed | "
        f"{contradicted} contradicted (auto-marked FP)"
    )
    return result


_SECURITY_HEADERS = {
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
    "cross-origin-opener-policy", "cross-origin-resource-policy",
}
_HDRS = {"User-Agent": "Mozilla/5.0 SecurityProbe/1.0"}


def _revalidate_finding(finding: dict) -> dict:
    """
    Make a live HTTP request and verify the finding's condition still holds.
    Returns the finding with revalidation_status set and confidence adjusted.
    """
    ftype    = finding.get("type", "")
    evidence = finding.get("evidence") or {}
    url      = finding.get("url", "")

    if not url:
        return {**finding, "revalidation_status": "inconclusive"}

    # ── Missing security header ────────────────────────────────────────────────
    if ftype == "missing_security_header" or evidence.get("missing_header"):
        header_name = (evidence.get("missing_header") or "").lower()
        if not header_name:
            # Infer from finding name
            name_lower = finding.get("name", "").lower()
            for h in _SECURITY_HEADERS:
                if h.replace("-", " ") in name_lower:
                    header_name = h
                    break

        if header_name:
            try:
                resp = httpx.get(url, headers=_HDRS, timeout=8, follow_redirects=True)
                resp_hdrs = {k.lower() for k in resp.headers}
                if header_name in resp_hdrs:
                    return {
                        **finding,
                        "revalidation_status": "contradicted",
                        "fp_status":           "likely_false_positive",
                        "fp_reason":           f"Re-verification found '{header_name}' present in live response.",
                        "confidence_score":    0.2,
                    }
                return {
                    **finding,
                    "revalidation_status": "confirmed",
                    "confidence_score":    _clamp(float(finding.get("confidence_score") or 0.5) + 0.10),
                }
            except httpx.RequestError:
                pass

    # ── Exposed sensitive path ─────────────────────────────────────────────────
    if evidence.get("type") in ("sensitive_path", "sensitive_path_restricted"):
        try:
            resp = httpx.get(url, headers=_HDRS, timeout=8, follow_redirects=False)
            if resp.status_code == 200:
                return {
                    **finding,
                    "revalidation_status": "confirmed",
                    "confidence_score":    _clamp(float(finding.get("confidence_score") or 0.5) + 0.10),
                }
            return {
                **finding,
                "revalidation_status": "contradicted",
                "fp_status":           "likely_false_positive",
                "fp_reason":           f"Re-verification returned HTTP {resp.status_code} — path no longer accessible.",
                "confidence_score":    0.2,
            }
        except httpx.RequestError:
            pass

    return {**finding, "revalidation_status": "inconclusive"}


# ── Stage 3: LLM analysis ─────────────────────────────────────────────────────

def _analyse_single(llm, finding: dict) -> dict:
    """Ask the LLM to evaluate one finding. Returns finding with LLM fields added."""
    summary = _build_finding_summary(finding)

    user_prompt = f"""Fill in this JSON template about the finding:

{summary}

Fill in values (do NOT add thinking, do NOT explain, ONLY output JSON):
{{
  "confidence_score": <number from 0.0 to 1.0>,
  "fp_status": "confirmed|likely_false_positive|uncertain",
  "fp_reason": "brief reason",
  "ai_description": "technical description",
  "ai_impact": "business impact",
  "ai_remediation": "how to fix it",
  "exploit_feasibility": "exploitable|requires_conditions|not_exploitable",
  "feasibility_reason": "one sentence explaining why"
}}"""

    result = llm.chat_json(
        system=_SYSTEM_PROMPT,
        user=user_prompt,
        temperature=0.1,
    )

    if not result:
        logger.debug(f"[FP-AGENT] No JSON response for: {finding.get('name')}")
        return finding

    updated = dict(finding)
    updated["ai_confidence_score"] = _clamp(result.get("confidence_score", finding.get("confidence_score", 0.5)))
    updated["fp_status"]           = result.get("fp_status", "uncertain")
    updated["fp_reason"]           = result.get("fp_reason", "")
    updated["exploit_feasibility"] = result.get("exploit_feasibility", "")
    updated["feasibility_reason"]  = result.get("feasibility_reason", "")

    if result.get("ai_description"):
        updated["ai_description"] = result["ai_description"]
        if len(updated.get("description", "")) < 80:
            updated["description"] = result["ai_description"]

    if result.get("ai_impact"):
        updated["impact"] = result["ai_impact"]

    if result.get("ai_remediation"):
        updated["ai_remediation"] = result["ai_remediation"]
        if len(updated.get("solution", "")) < 60:
            updated["solution"] = result["ai_remediation"]

    updated["confidence_score"] = updated["ai_confidence_score"]
    updated["llm_analysed"]     = True

    logger.debug(
        f"[FP-AGENT] '{finding.get('name')}' → "
        f"conf={updated['confidence_score']:.2f} | status={updated['fp_status']} | "
        f"feasibility={updated['exploit_feasibility']}"
    )
    return updated


def _build_finding_summary(f: dict) -> str:
    """Build a compact text summary of a finding for the LLM prompt."""
    lines = [
        f"Name: {f.get('name', 'Unknown')}",
        f"Severity: {f.get('severity', 'Unknown')}",
        f"Module: {f.get('module', 'unknown')} | Tool: {f.get('tool_used', 'unknown')}",
        f"Target URL: {f.get('url', 'N/A')}",
        f"CVSS Score: {f.get('cvss_score', 'N/A')}",
        f"Current Description: {f.get('description', 'N/A')[:200]}",
    ]

    if f.get("tool_count") is not None:
        lines.append(f"Tool Count: {f['tool_count']} | Corroborated: {f.get('corroborated', False)}")
    if f.get("revalidation_status"):
        lines.append(f"Re-validation: {f['revalidation_status']}")
    if f.get("linked_findings"):
        lines.append(f"Linked findings on same URL: {len(f['linked_findings'])}")

    evidence = f.get("evidence", {})
    if evidence:
        if evidence.get("banner"):
            lines.append(f"Banner/Service Info: {evidence['banner'][:100]}")
        req = evidence.get("request") or evidence.get("request_header", "")
        if req:
            lines.append(f"HTTP Request:\n{req[:400]}")
        if evidence.get("response_header"):
            lines.append(f"HTTP Response Headers: {evidence['response_header'][:200]}")
        elif evidence.get("response_headers"):
            lines.append(f"Response Headers: {str(evidence['response_headers'])[:200]}")
        if not req and evidence.get("curl_poc"):
            lines.append(f"PoC Command: {evidence['curl_poc'][:150]}")

    return "\n".join(lines)


def _clamp(value, lo: float = 0.0, hi: float = 1.0) -> float:
    try:
        return max(lo, min(hi, float(value)))
    except (TypeError, ValueError):
        return 0.5
