"""
ReportAgent — LLM-driven report narrative generator.

Two modes:
  draft(session)    — called when scan reaches awaiting_validation;
                      generates narrative for all findings while the analyst
                      works through the Critical/High review queue
  finalise(session) — called after all reviewer decisions are submitted;
                      incorporates analyst outcomes (confirmed/rejected/downgraded)
                      into the executive summary and conclusion

Returns a narrative dict stored in session["report_narrative"].
report_generator.py reads this dict and injects it into all output formats.
No tools, no ReAct loop — pure LLM text generation via chat_json().
"""
import json
import logging

logger = logging.getLogger(__name__)

_DRAFT_SYSTEM_PROMPT = """You are a senior penetration tester writing the narrative sections of a security assessment report.

You will receive a JSON summary of a completed scan. Write professional, specific report narrative.

Output ONLY valid JSON with exactly these fields:
{
  "executive_summary":   "2-3 paragraphs: what was tested, what was found at a high level, overall risk posture",
  "attack_surface":      "1-2 paragraphs: external attack surface discovered — ports, services, technologies, entry points",
  "key_risks":           ["top risk 1 in plain English", "top risk 2", "top risk 3"],
  "remediation_roadmap": {
    "immediate": ["action for critical/high findings"],
    "30_days":   ["action for medium findings"],
    "90_days":   ["action for low/hygiene findings"]
  },
  "methodology_note":    "1 paragraph: tools and techniques used in this specific assessment",
  "draft":               true
}

Be specific — name the vulnerability types, severities, and affected components.
Write for a technical audience who will act on the findings. No filler phrases."""


_FINALISE_SYSTEM_PROMPT = """You are a senior penetration tester writing the final narrative for a completed security assessment report.

You will receive a JSON summary including analyst review decisions (confirmed, false_positive, downgrade, escalate).
Incorporate those decisions accurately: exclude false positives from risk statements, use updated severities for downgrades.

Output ONLY valid JSON with exactly these fields:
{
  "executive_summary":     "2-3 paragraphs: what was tested, confirmed findings after analyst review, updated risk posture",
  "attack_surface":        "1-2 paragraphs: confirmed attack surface after analyst review",
  "key_risks":             ["top confirmed risk 1", "risk 2", "risk 3"],
  "remediation_roadmap": {
    "immediate": ["critical/high confirmed — action"],
    "30_days":   ["medium confirmed — action"],
    "90_days":   ["low/hygiene — action"]
  },
  "analyst_summary":       "1-2 sentences: what the analyst confirmed vs rejected vs downgraded",
  "methodology_note":      "1 paragraph: tools and techniques used",
  "conclusion":            "1-2 paragraphs: overall conclusion and re-test recommendation",
  "draft":                 false
}

If all Critical/High findings were rejected as false positives, say so clearly and adjust the overall risk accordingly."""


class ReportAgent:

    def __init__(self, llm=None):
        self.llm = llm

    def draft(self, session: dict) -> dict:
        """
        Generate draft narrative immediately after the scan completes.
        Called by the orchestrator when the session reaches awaiting_validation.
        Returns a narrative dict; empty dict if no LLM configured.
        """
        if not self.llm:
            return {}
        try:
            narrative = self.llm.chat_json(
                system      = _DRAFT_SYSTEM_PROMPT,
                user        = _build_draft_prompt(session),
                temperature = 0.3,
                max_tokens  = 1600,
            )
            if narrative and isinstance(narrative, dict):
                logger.info(
                    f"[REPORT_AGENT] Draft narrative ready for session "
                    f"{session.get('session_id')} — "
                    f"{len(narrative.get('key_risks', []))} key risks"
                )
                return narrative
        except Exception as e:
            logger.warning(f"[REPORT_AGENT] Draft generation failed: {e}")
        return {}

    def finalise(self, session: dict) -> dict:
        """
        Generate final narrative after analyst decisions are applied.
        Called by the /review endpoint when queue["complete"] is True.
        Returns updated narrative dict; falls back to existing draft if generation fails.
        """
        if not self.llm:
            return session.get("report_narrative", {})
        try:
            narrative = self.llm.chat_json(
                system      = _FINALISE_SYSTEM_PROMPT,
                user        = _build_finalise_prompt(session),
                temperature = 0.2,
                max_tokens  = 1800,
            )
            if narrative and isinstance(narrative, dict):
                logger.info(
                    f"[REPORT_AGENT] Final narrative ready for session "
                    f"{session.get('session_id')} — draft=False"
                )
                return narrative
        except Exception as e:
            logger.warning(f"[REPORT_AGENT] Finalise generation failed: {e}")
        return session.get("report_narrative", {})


# ── Prompt builders ────────────────────────────────────────────────────────────

def _build_draft_prompt(session: dict) -> str:
    summary  = session.get("summary", {})
    findings = session.get("enriched_findings", [])

    finding_summaries = [
        {
            "name":     f.get("name"),
            "severity": f.get("severity"),
            "type":     f.get("type"),
            "module":   f.get("module"),
            "cvss":     f.get("cvss_score"),
            "url":      f.get("url"),
        }
        for f in findings[:30]   # cap to stay within token budget
    ]

    data = {
        "target":             session.get("target"),
        "scan_mode":          session.get("scan_mode"),
        "agents_run":         session.get("agents_executed", []),
        "severity_breakdown": summary.get("severity_breakdown", {}),
        "risk_rating":        summary.get("risk_rating"),
        "risk_score":         summary.get("overall_risk_score"),
        "total_findings":     len(findings),
        "findings":           finding_summaries,
    }
    return f"Generate a draft narrative for this scan:\n{json.dumps(data, default=str)}"


def _build_finalise_prompt(session: dict) -> str:
    summary  = session.get("summary", {})
    findings = session.get("enriched_findings", [])

    confirmed  = sum(1 for f in findings if f.get("review_status") == "confirm")
    rejected   = sum(1 for f in findings if f.get("review_status") == "false_positive")
    downgraded = sum(1 for f in findings if f.get("review_status") == "downgrade")
    escalated  = sum(1 for f in findings if f.get("review_status") == "escalate")

    finding_summaries = [
        {
            "name":          f.get("name"),
            "severity":      f.get("severity"),
            "type":          f.get("type"),
            "module":        f.get("module"),
            "cvss":          f.get("cvss_score"),
            "review_status": f.get("review_status", "pending"),
        }
        for f in findings[:30]
    ]

    data = {
        "target":               session.get("target"),
        "scan_mode":            session.get("scan_mode"),
        "agents_run":           session.get("agents_executed", []),
        "severity_breakdown":   summary.get("severity_breakdown", {}),
        "risk_rating":          summary.get("risk_rating"),
        "risk_score":           summary.get("overall_risk_score"),
        "total_findings":       len(findings),
        "confirmed_count":      confirmed,
        "false_positive_count": rejected,
        "downgraded_count":     downgraded,
        "escalated_count":      escalated,
        "findings":             finding_summaries,
    }
    return f"Generate the final narrative for this completed assessment:\n{json.dumps(data, default=str)}"
