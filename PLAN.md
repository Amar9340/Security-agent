# AI-Driven VAPT Platform — Project Plan

## Overview

An AI-powered Vulnerability Assessment & Penetration Testing platform that:
- Runs full scans, checklist-based scans, single-vulnerability scans, and OWASP-mode scans
- Uses AI agents to orchestrate testing and triage findings
- Integrates ZAP, Nuclei, Nmap, and Prowler
- Produces company-standard reports (JSON / HTML / CSV / PDF)
- Learns from analyst feedback (Phase 4)

---

## Architecture

```
Streamlit UI  ←→  FastAPI (main.py)
                       ↓
               Orchestrator (orchestrator.py)
                       ↓
         Knowledge Agent (test selection)
                       ↓
     ┌─────────────────┼─────────────────┐
  Web Agent       Network Agent      Cloud Agent
  (ZAP, Nuclei,   (Nmap)             (Prowler)
   HTTP probes)
     └─────────────────┼─────────────────┘
                       ↓
              Enrichment (CVSS v3.1)
                       ↓
              FP Agent (3-stage pipeline)
                       ↓
              Reviewer Agent (human triage)
                       ↓
              Report Generator
                       ↓
              Database (SQLAlchemy / SQLite → PostgreSQL)
```

---

## Core Design Rules

1. **Checklist is primary** — canonical names only, no free-text vulnerabilities
2. **Standards fallback** — OWASP WSTG / NIST when no checklist item applies
3. **Agents are domain-isolated** — Web ≠ Network ≠ Cloud
4. **No raw tool output** — every finding normalized through agents
5. **All findings must include PoC + CVSS score**
6. **High severity (CVSS ≥ 7.0) must be human-validated**

---

## Scan Modes

| Mode       | Description                                              |
|------------|----------------------------------------------------------|
| full       | All agents run all tests                                 |
| checklist  | Runs only the specified checklist items                  |
| single     | One vulnerability by name (e.g. "SQL Injection")         |
| owasp      | OWASP Top 10 coverage pass                               |

Scan depth: `quick` / `standard` / `deep`

---

## Tech Stack

- **Backend:** FastAPI + Python
- **UI:** Streamlit (Forest Green + Gold theme)
- **Database:** SQLAlchemy ORM — SQLite default, PostgreSQL-ready
- **AI/LLM:** Provider-agnostic client — fallback chain: groq → gemini → openrouter → ollama
- **Tools:** ZAP, Nuclei v3, Nmap, Prowler
- **Deployment:** Docker Compose (FastAPI + PostgreSQL + Ollama)

---

## Component Status

### Complete

| Component | File | Notes |
|-----------|------|-------|
| FastAPI REST API v4 | `main.py` | Sessions, scans, validate, reports |
| Orchestrator v3 | `orchestrator.py` | Coordinates full pipeline |
| Knowledge Agent | `agents/knowledge_agent.py` | Checklist primary, OWASP/NIST fallback |
| FP Agent (3-stage) | `agents/fp_agent.py` | Correlation → HTTP re-verify → LLM analysis |
| Reviewer Agent | `agents/reviewer_agent.py` | Triage queue, analyst decisions, escalation |
| LLM Client | `agents/llm_client.py` | Circuit breaker, retry, TTL cache, fallback chain |
| Recon Module | `modules/recon.py` | Endpoint discovery, headers, tech fingerprint |
| Web Module | `modules/web_module.py` | ZAP + Nuclei + HTTP probes |
| Network Module | `modules/network_module.py` | Nmap |
| Cloud Module | `modules/cloud_module.py` | Prowler |
| HTTP Probes | `modules/probes.py` | 39 WSTG-aligned probes, @register registry |
| Enrichment | `enrichment.py` | CVSS v3.1 + confidence scoring |
| Report Generator | `report_generator.py` | JSON / HTML / CSV / PDF |
| Streamlit UI | `ui/app.py` | Scan / Dashboard / Review / Export pages |
| Database layer | `database/` | SQLAlchemy ORM, migration-ready |
| Docker Compose | `docker-compose.yml` | One-command deployment |

### Remaining (Phase 3)

- [ ] **Performance:** parallel LLM batch processing, Redis caching, DB indexing, connection pooling
- [ ] **Dashboard UI:** live scan progress, risk heat maps, report download centre
- [ ] **Test suite:** 60 %+ coverage; automated tests against DVWA / WebGoat / Juice Shop
- [ ] **Health check endpoint:** `GET /health` — DB + LLM + tool availability
- [ ] **Structured logging** with rotation
- [ ] **probes.py bug fixes (Session B–D):** 31 logic bugs, FP reductions, and missing functionality items from audit report

---

## WSTG Probe Coverage

39 of 94 WSTG v4.1 IDs are covered by HTTP probes in `modules/probes.py`.
The remaining 55 are not automatable via blind HTTP probes — they require browser
execution, app-specific business logic knowledge, or OS/server-level access.

See `agents/fp_agent.py` docstring and memory for the full exclusion rationale.

---

## Known Issues / Blockers

| Priority | Issue |
|----------|-------|
| Critical | External tool (ZAP/Nmap) timeouts — needs circuit breaker + retry backoff |
| High | 100+ findings cause >30s LLM latency — needs parallel batch processing |
| High | PostgreSQL migration untested (Docker Compose exists, migration path not validated) |
| Medium | Confidence score calibration needs analyst feedback data |
| Medium | SQLi probe misses URLs with no query params — needs common-param fallback |
| Medium | ZAP passive scan runs regardless of scan mode — header findings bleed into single-vuln scans |

---

## Key Design Decisions

- **Evidence Agent not built as standalone** — evidence captured inline at source in each module; centralising would add overhead with zero new capability
- **LLM only for Critical/High findings** — Medium/Low/Info keep heuristic scores to stay within free-tier rate limits
- **FP Agent Stage 2 skips probe findings** — probes are already direct HTTP checks; re-verification would be redundant
- **Nuclei runs alongside ZAP** — findings are deduplicated before enrichment

---

## Phase 4 (Future)

- Learning Agent — feedback loop from analyst decisions to improve detection and scoring
- Attack chaining — multi-step exploit sequences
- Continuous monitoring mode
- Dashboard analytics
- Multi-tenant support
