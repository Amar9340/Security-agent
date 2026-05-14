# AI-Driven VAPT Platform — Redesign Plan & Progress

## What We're Building

Replace every hardcoded decision in the pipeline with LLM reasoning.  
**Before:** Python decides what to test, how to test it, and what it means.  
**After:** LLM decides. Python executes tool calls and enforces schema.

---

## Target Architecture

```
FastAPI / Streamlit UI
         ↓
Orchestrator  (thin — sequences agents, no security logic)
         ↓
Agent Loop  (ReAct: THINK → TOOL CALL → OBSERVE → repeat)
         ↓
┌─────────────────────────────────────────────────────┐
│  Recon Agent  Web Agent  Network Agent  Cloud Agent  │
│  (all LLM-driven, call tools, report_finding())      │
└─────────────────────────────────────────────────────┘
         ↓
Enrichment  (CVSS formula — stays hardcoded, not LLM)
         ↓
         ├── Critical / High  →  Human Review Queue
         │     Reviewer Agent (LLM) writes a brief per finding
         │     Analyst: confirm / false_positive / downgrade / escalate / needs_retest
         │
         └── Medium / Low / Info  →  Report Agent (draft mode, starts immediately)
                    ↓
         After review complete → Report Agent (finalise mode)
                    ↓
         Final Report  (JSON / HTML / CSV / PDF)
```

---

## Tool Set  (replaces probes.py + all module logic)

| Tool | File | Replaces |
|------|------|---------|
| `http_request` | `agents/tools/http_tool.py` | All 47 probes in `probes.py` |
| `dns_lookup` | `agents/tools/dns_tool.py` | DNS logic in `recon.py` |
| `ssl_check` | `agents/tools/ssl_tool.py` | `probe_weak_tls` in `probes.py` |
| `search_cve` | `agents/tools/cve_tool.py` | 6-entry hardcoded dict in `network_module.py` |
| `run_nmap` | `agents/tools/nmap_tool.py` | `network_module.py` scan logic |
| `run_nuclei` | `agents/tools/nuclei_tool.py` | Nuclei call in `web_module.py` |
| `run_zap` | `agents/tools/zap_tool.py` | ZAP call in `web_module.py` |
| `run_prowler` | `agents/tools/prowler_tool.py` | `cloud_module.py` (+ mock data removed) |
| `report_finding` | `agents/tools/finding_tool.py` | Output contract — all agents use this |

---

## Human-in-the-Loop Flow

1. Scan completes → findings split into two parallel tracks
2. **Critical / High** → Review Queue  
   Reviewer Agent (LLM) writes a brief: evidence summary, confidence, attack chain context, suggested decision with reasoning
3. **Medium / Low / Info** → Report Agent starts draft immediately (no waiting)
4. Analyst works through queue in UI:  
   `confirm` / `false_positive` / `downgrade` / `escalate` / `needs_retest`
5. After all Critical/High reviewed → Report Agent finalises (merges analyst decisions into full report)

**Session states:**  
`running → scanning → enrichment → awaiting_review`  
→ `draft_ready` (parallel with review) → `review_complete` → `report_finalised`

---

## Implementation Phases

---

### ✅ Phase 1 — Foundation  *(COMPLETE)*
The agent engine and all tool wrappers. Nothing wired to the orchestrator yet —  
this is the infrastructure everything else builds on.

| Part | File | What it does |
|------|------|-------------|
| 1A | `agents/base_agent.py` | ReAct loop engine — THINK → TOOL CALL → OBSERVE |
| 1B | `agents/tool_registry.py` | Collects tool functions into `{name: callable}` dict |
| 1C | `agents/tools/http_tool.py` | HTTP request with Python-level scope enforcement |
| 1C | `agents/tools/finding_tool.py` | Output contract schema for all agents |
| 1D | `agents/tools/dns_tool.py` | DNS lookups (A/AAAA/MX/NS/TXT/CNAME/SOA/PTR) |
| 1D | `agents/tools/ssl_tool.py` | TLS cert inspection + protocol version probing |
| 1D | `agents/tools/cve_tool.py` | Live NVD API CVE lookup |
| 1E | `agents/tools/nmap_tool.py` | Nmap subprocess wrapper (XML output → structured dict) |
| 1E | `agents/tools/nuclei_tool.py` | Nuclei subprocess wrapper (JSONL → structured findings) |
| 1E | `agents/tools/zap_tool.py` | OWASP ZAP API wrapper (spider / passive / active) |
| 1E | `agents/tools/prowler_tool.py` | Prowler cloud audit wrapper (FAIL findings only) |
| 1F | `agents/llm_client.py` | Added `chat_with_tools()` — native tool calling for all 4 providers |

**Key design decisions made in Phase 1:**
- Scope enforcement is Python-level in `http_tool.py` — LLM cannot override it
- `report_finding()` is intercepted by `BaseAgent` before the function body runs — schema validated internally
- Ollama: tries native tool calling first, falls back to prompt injection
- `_build_tool_prompt()` injects full schemas into system prompt for prompt-based fallback

---

### ⬜ Phase 2 — Recon Agent  *(NEXT)*
**New file:** `agents/recon_agent.py`  
**Retires:** `modules/recon.py`

The LLM decides what recon steps to take based on the target. No more hardcoded socket calls and header checks in sequence.

Tools available: `dns_lookup`, `ssl_check`, `http_request`, `report_finding`

What the LLM will do:
- Query DNS records (A, MX, NS, TXT for SPF/DKIM/DMARC)
- Check TLS cert and protocol versions
- Probe HTTP headers (security headers, server banners, CORS)
- Report findings: missing headers, weak TLS, info disclosure, open redirects

---

### ⬜ Phase 3 — Web Agent
**New file:** `agents/web_agent.py`  
**Retires:** `modules/web_module.py` detection logic, `modules/probes.py`

Tools available: `http_request`, `run_zap`, `run_nuclei`, `report_finding`

The LLM replaces all 47 hardcoded probes. It crafts its own HTTP requests based on what it observes, interprets ZAP and Nuclei output, and decides what is a real finding vs noise.

---

### ⬜ Phase 4A — Network Agent
**New file:** `agents/network_agent.py`  
**Retires:** `modules/network_module.py` analysis logic

Tools available: `run_nmap`, `search_cve`, `http_request`, `report_finding`

The LLM reads Nmap output, looks up CVEs for detected service versions, and decides which are exploitable in context.

---

### ⬜ Phase 4B — Cloud Agent
**New file:** `agents/cloud_agent.py`  
**Retires:** `modules/cloud_module.py` (including 6 hardcoded mock findings)

Tools available: `run_prowler`, `report_finding`

The LLM evaluates Prowler FAIL findings, prioritises by real-world risk, and writes analyst-quality findings.

---

### ⬜ Phase 5 — Remove Knowledge Agent
**Deletes:** `agents/knowledge_agent.py`  
**Demotes:** `checklist/registry.json` from runtime dependency to prompt reference  
**Simplifies:** `orchestrator.py` — no more `ExecutionPlan`, agents self-direct

The LLM decides what to test based on recon data and scan mode. The WSTG checklist becomes context in the system prompt, not a lookup table.

---

### ⬜ Phase 6 — Reviewer Agent + Human-in-the-Loop Gate
**Rewrites:** `agents/reviewer_agent.py` (currently 3 if-statements + state machine)  
**Deletes:** `agents/fp_agent.py` (LLM handles FP detection now)  
**Updates:** `main.py` (review endpoints), `ui/app.py` (Review Queue + Report Preview tabs), `database/` (review state fields)

For each Critical/High finding the LLM writes a structured brief:
- Evidence summary, confidence assessment, attack chain context
- Related findings, suggested analyst decision with reasoning

Analyst sees two tabs: Review Queue (work through Critical/High) + Report Preview (draft already visible).

---

### ⬜ Phase 7 — Report Agent
**New file:** `agents/report_agent.py`  
**Updates:** `report_generator.py` (accepts LLM narrative)

**Draft mode** (immediate, Medium/Low/Info): narrative sections, attack surface summary, remediation roadmap  
**Finalise mode** (after review complete): merges analyst decisions, updates risk score, generates JSON/HTML/CSV/PDF

---

## Complete File Change Summary

| File | Action | Phase | State |
|------|--------|-------|-------|
| `agents/base_agent.py` | New — ReAct loop engine | 1 | ✅ Done |
| `agents/tool_registry.py` | New — tool dict builder | 1 | ✅ Done |
| `agents/tools/http_tool.py` | New | 1 | ✅ Done |
| `agents/tools/finding_tool.py` | New | 1 | ✅ Done |
| `agents/tools/dns_tool.py` | New | 1 | ✅ Done |
| `agents/tools/ssl_tool.py` | New | 1 | ✅ Done |
| `agents/tools/cve_tool.py` | New | 1 | ✅ Done |
| `agents/tools/nmap_tool.py` | New | 1 | ✅ Done |
| `agents/tools/nuclei_tool.py` | New | 1 | ✅ Done |
| `agents/tools/zap_tool.py` | New | 1 | ✅ Done |
| `agents/tools/prowler_tool.py` | New | 1 | ✅ Done |
| `agents/llm_client.py` | Updated — `chat_with_tools()` added | 1 | ✅ Done |
| `agents/recon_agent.py` | New — LLM recon | 2 | ⬜ Next |
| `modules/recon.py` | Deleted | 2 | ⬜ |
| `agents/web_agent.py` | New — LLM web scanning | 3 | ⬜ |
| `modules/web_module.py` | Gutted (wrappers stay, analysis deleted) | 3 | ⬜ |
| `modules/probes.py` | Deleted | 3 | ⬜ |
| `agents/network_agent.py` | New — LLM network scanning | 4A | ⬜ |
| `modules/network_module.py` | Gutted (Nmap wrapper stays) | 4A | ⬜ |
| `agents/cloud_agent.py` | New — LLM cloud audit | 4B | ⬜ |
| `modules/cloud_module.py` | Gutted (Prowler wrapper stays, mock data deleted) | 4B | ⬜ |
| `agents/knowledge_agent.py` | Deleted | 5 | ⬜ |
| `checklist/registry.json` | Demoted to prompt reference | 5 | ⬜ |
| `orchestrator.py` | Simplified — no security logic | 5 | ⬜ |
| `agents/reviewer_agent.py` | Rewritten as LLM agent | 6 | ⬜ |
| `agents/fp_agent.py` | Deleted | 6 | ⬜ |
| `main.py` | Updated — review queue endpoints | 6 | ⬜ |
| `ui/app.py` | Updated — Review Queue + Report Preview tabs | 6 | ⬜ |
| `database/` | Minor — review state fields | 6 | ⬜ |
| `agents/report_agent.py` | New — LLM report narrative | 7 | ⬜ |
| `report_generator.py` | Minor — accepts LLM narrative | 7 | ⬜ |
| `enrichment.py` | Unchanged — CVSS formula stays | — | — |

---

## What Stays Hardcoded (Intentionally)

| What | Where | Why |
|------|-------|-----|
| CVSS v3.1 formula | `enrichment.py` | Standard formula, not a judgment call |
| Scope enforcement | `agents/tools/http_tool.py` | Python guardrail — must not be LLM-controlled |
| Finding schema validation | `report_finding()` in `BaseAgent` | Structural contract |
| Rate limiting + circuit breakers | `agents/llm_client.py` | Infrastructure |

---

## Rollback

Last stable commit before redesign started: `620083d` on `main`  
All Session B–F probe bug fixes are in this commit.

```
git checkout -b revert-to-original 620083d
```
