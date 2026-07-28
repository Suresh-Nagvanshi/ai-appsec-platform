# AI AppSec Platform

AI-powered Application Security platform that combines traditional static analysis
with contextual AI reasoning for vulnerability prioritization, exploitability
analysis, and remediation guidance.

---

## Vision

Traditional security tools generate large volumes of raw findings:

- False positives
- Duplicate issues
- Low-priority alerts
- Difficult remediation paths

This platform transforms raw scanner output into:

- Contextual, enriched findings
- Exploitability-aware AI analysis
- AI-assisted remediation guidance
- Actionable security intelligence

The long-term objective is to function as an AI-assisted security engineer,
not a simple scanner.

---

## Current Architecture (MVP)

```text
GitHub Repository URL  ──or──  ZIP File Upload
                        │
                        ▼
             Clone / Extract to disk
                        │
                        ▼
           Semgrep Static Analysis
                        │
                        ▼
          Findings Normalization
                        │
                        ▼
          Context Enrichment Layer
        ├── Framework Detection
        ├── Endpoint Extraction
        ├── Snippet Extraction
        └── Context Builder
                        │
                        ▼
           Risk Scoring Engine
                        │
                        ▼
            AI Analysis Layer  (Groq API)
        ├── Model Router
        ├── Prompt Builder
        ├── Analysis Engine
        └── Response Parser
                        │
                        ▼
           Deduplication Layer
                        │
                        ▼
           Findings Repository  (JSON)
                        │
                        ▼
              Reporting Layer
                        │
                        ▼
           Frontend Dashboard  (Next.js)
```

---

## Technology Stack

### Backend

- Python 3.11+
- FastAPI
- Groq API (LLaMA 3.1 / 3.3)
- JSON file storage (temporary — PostgreSQL planned)
- Semgrep (must be installed separately — see setup)

### Frontend

- Next.js 14 (App Router)
- TypeScript
- Tailwind CSS
- React Query

### AI / Security

- Semgrep (static analysis)
- OWASP vulnerability mapping
- MITRE ATT&CK references
- AI reasoning via Groq API

---

## Local Development Setup

### Prerequisites

| Tool | Required version | Notes |
|---|---|---|
| Python | 3.11 or 3.12 recommended | 3.13 works but Semgrep pip install may vary |
| Node.js | 18+ | For frontend |
| Semgrep | 1.38.0+ | **Must be on system PATH** — see note below |
| Git | Any recent version | For repository cloning |

> **Important — Semgrep installation:**
> Semgrep must be installed and accessible as `semgrep` on your system PATH.
> The platform calls `semgrep` directly as a binary (not `python -m semgrep`,
> which was deprecated in Semgrep 1.38.0).
>
> Install Semgrep:
> ```bash
> pip install semgrep
> ```
> Verify it works:
> ```bash
> semgrep --version
> ```

---

### 1. Clone the repository

```bash
git clone https://github.com/Suresh-Nagvanshi/ai-appsec-platform.git
cd ai-appsec-platform
```

---

### 2. Backend setup

```bash
pip install -r requirements.txt
```

Create a `.env` file in the project root:

```env
GROQ_API_KEY=your_groq_api_key_here
```

Get a free Groq API key at: https://console.groq.com

---

### 3. Start the backend

> ⚠️ **Use `python -m backend.run` — NOT `uvicorn backend.main:app --reload` directly.**
>
> The custom launcher (`backend/run.py`) configures `reload_excludes` to prevent
> uvicorn from watching cloned repository files and extracted ZIP contents.
> Running uvicorn directly causes WatchFiles to trigger server reloads mid-scan,
> killing in-progress scans.

```bash
python -m backend.run
```

Backend API will be available at:

```
http://127.0.0.1:8000
```

API docs (auto-generated):

```
http://127.0.0.1:8000/docs
```

---

### 4. Frontend setup

```bash
cd frontend
```

Create the frontend environment file from the example:

```bash
cp .env.local.example .env.local
```

Then edit `frontend/.env.local` and set:

```env
NEXT_PUBLIC_API_URL=http://localhost:8000
NEXT_PUBLIC_API_KEY=your_api_key_here
```

Install dependencies and start the dev server:

```bash
npm install
npm run dev
```

Frontend will be available at:

```
http://localhost:3000
```

---

## Current Project Status

**Phase:** MVP — GitHub URL scanning + ZIP upload scanning

**Status:** Actively under development

### What is working

| Feature | Status |
|---|---|
| GitHub repository URL scanning | ✅ Working |
| ZIP file upload scanning | ✅ Working |
| Semgrep static analysis | ✅ Working |
| Context enrichment pipeline | ✅ Wired |
| Risk scoring | ✅ Wired |
| AI analysis via Groq (LLaMA 3.3 70B / 3.1 8B) | ✅ Wired |
| Finding deduplication | ✅ Wired |
| Findings persistence (JSON) | ✅ Wired |
| Scan state persistence across restarts | ✅ Fixed |
| Frontend scan session page | ✅ Working |
| Frontend findings dashboard | ✅ Working |
| Scan progress polling | ✅ Working |

### Known limitations (MVP scope)

| Limitation | Notes |
|---|---|
| No authentication | All endpoints are public — do not expose publicly |
| In-memory scan state | Persisted to `data/scan_state.json`; lost only on manual file delete |
| JSON storage | Will be replaced with PostgreSQL |
| No file size limits | Large repositories / ZIPs will take significant time |
| AI analysis is synchronous per-finding | Large repos with many findings will be slow |

---

## Implemented Components

### Backend

- FastAPI application with full scan pipeline
- GitHub repository URL scan endpoint (`POST /api/scans/github`)
- ZIP file upload scan endpoint (`POST /api/scans/file`)
- Scan state polling endpoint (`GET /api/scans/{scan_id}`)
- Scan list endpoint (`GET /api/scans`)
- Findings API (`GET /findings`)
- Report generation endpoint
- Scan state persistence (`data/scan_state.json`)

### AI Layer

- Prompt Builder
- Response Parser
- Analysis Engine
- Async Analysis Engine
- Batch Analysis Engine
- Model Router (routes simple findings to LLaMA 3.1 8B, complex to LLaMA 3.3 70B)

### Context Enrichment

- Framework Detection
- Endpoint Extraction
- Snippet Extraction
- Context Builder

### Security Processing

- Risk Scoring Engine
- Finding Deduplicator
- Findings Repository
- Report Generator

### Frontend

- Security Dashboard (Overview)
- Scan session page with live pipeline steps + logs
- Findings list and detail pages
- Repositories page
- Reports page
- Real-time scan progress polling via React Query

---

## Directory Structure

```text
ai-appsec-platform/
├── backend/
│   ├── main.py                  # FastAPI app entrypoint
│   ├── run.py                   # Uvicorn launcher (use this to start)
│   ├── api/
│   │   ├── scans.py             # Scan endpoints
│   │   ├── scan_state.py        # Shared in-memory + disk scan state
│   │   └── findings.py          # Findings endpoints (currently serving mock + real)
│   ├── services/
│   │   └── scan_orchestrator.py # Full scan pipeline wiring
│   ├── ai/
│   │   ├── analysis_engine.py
│   │   ├── prompt_builder.py
│   │   ├── response_parser.py
│   │   └── model_router.py
│   ├── enrichment/
│   │   └── context_builder.py
│   ├── risk/
│   │   └── risk_scorer.py
│   ├── deduplication/
│   │   └── finding_deduplicator.py
│   └── storage/
│       └── findings_repository.py
├── frontend/
│   └── src/
│       ├── app/                 # Next.js App Router pages
│       ├── components/          # Shared UI components
│       ├── hooks/               # React Query hooks
│       └── services/            # API service layer
├── data/
│   └── scan_state.json          # Persisted scan state (auto-created)
├── results/                     # Semgrep raw output (auto-created)
├── repos/                       # Cloned repositories (auto-created, auto-cleaned)
├── uploads/                     # ZIP uploads (auto-created, auto-cleaned)
├── extracted/                   # Extracted ZIP contents (auto-created, auto-cleaned)
└── .env                         # Environment variables (create manually)
```

---

## Bug Fixes Applied

### Fix 1 — Semgrep deprecated invocation (May 2026)

**Problem:** Semgrep was called as `python -m semgrep`, which was deprecated in
Semgrep 1.38.0. On Windows with a bundled Semgrep binary, this also caused a
fatal `Failed to import the site module` crash due to Python environment variable
pollution (`PYTHONUTF8`, `PYTHONIOENCODING`).

**Fix:** Semgrep is now called as the `semgrep` binary directly. The subprocess
environment no longer injects Python-specific encoding variables.

### Fix 2 — Scan state lost on server restart (May 2026)

**Problem:** Scan state was held in an in-memory dict only. Uvicorn `--reload`
was triggered by WatchFiles detecting file writes in the `repos/` directory
(from cloning), killing the running scan and wiping all scan state.

**Fix:**
- Created `backend/run.py` launcher with `reload_excludes` for `repos/`,
  `extracted/`, `uploads/`, `results/`, `data/`, `*.json`
- Added disk persistence to `backend/api/scan_state.py` — scan state is
  written to `data/scan_state.json` after every mutation and loaded on startup

### Fix 3 — Circular import on startup (May 2026)

**Problem:** `backend/api/scans.py` and `backend/services/scan_orchestrator.py`
imported each other, causing an `ImportError` on startup.

**Fix:** Shared `_scans` dict moved to `backend/api/scan_state.py`. Both modules
import from the neutral shared module — no cycle.

---

## In Progress

- Replace mock findings in `GET /findings` with real persisted data
- Findings detail page connected to real API
- PostgreSQL integration
- Docker setup
- Authentication and API key middleware
- RBAC
- Multi-tenant isolation

---

## Planned Features

### Repository Security

- Branch selection
- Incremental / diff scanning
- GitHub App integration

### Website Security

- Website URL scanner
- Crawling engine
- Client-side vulnerability analysis

### API Security

- Endpoint discovery
- OWASP API Top 10 mapping
- Authentication and authorization testing

### AI/ML Security Testing

- Prompt injection testing
- Jailbreak testing
- Model behavior evaluation
- Safety assessment

### Enterprise Features

- Organization and team management
- RBAC
- Audit logs
- CI/CD integrations
- Webhooks

---

## Contributing

Maintained by **Suresh Nagvanshi**.
