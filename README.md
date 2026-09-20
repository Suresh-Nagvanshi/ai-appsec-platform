# AI AppSec Platform

AI AppSec Platform is a comprehensive application-security workspace that combines static analysis, contextual AI reasoning, attack-surface discovery, runtime evidence, and developer remediation workflows.

The platform is designed to help security and engineering teams move from **finding** to **evidence**, **prioritization**, and **verified remediation**.

## Contents

- [Capabilities](#capabilities)
- [Architecture](#architecture)
- [Database Design](#database-design)
- [Technology Stack](#technology-stack)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [API Surface](#api-surface)
- [Frontend](#frontend)
- [Project Structure](#project-structure)
- [Security Boundaries](#security-boundaries)
- [Testing](#testing)
- [Roadmap](#roadmap)
- [Troubleshooting](#troubleshooting)

## Capabilities

### Repository Security
- GitHub repository scanning with branch selection
- ZIP upload scanning with file-count, archive-size, and extracted-size limits
- Semgrep static analysis
- Framework, endpoint, snippet, and source-context enrichment
- Risk scoring, AI analysis, deduplication, and finding triage

### Website & API Security
- Public website URL scanning with bounded breadth-first crawling
- Security-header analysis (CSP, HSTS, clickjacking) and DOM sinks
- Static endpoint discovery (Spring Boot, Express.js, FastAPI)
- OWASP API Top 10 mapping and OpenAPI contract drift detection

### AI and ML Security
- Prompt-injection, jailbreak probes, and model behavior evaluation
- Safety and refusal assessment

### Security Operations and Developer Workflows
- Unified security graph connecting scans, findings, endpoints, and repositories
- Candidate attack-path generation
- Automated GitHub security-fix pull requests
- CycloneDX/SPDX dependency inventory and secrets detection
- Docker, Terraform, Kubernetes, and CI workflow checks
- Exploit-validation sandbox (Docker isolated)

## Architecture

The platform operates on a 6-tier pipeline, seamlessly routing data from the frontend to external integrations.

```text
┌──────────────────────────────────────────────────────────┐
│ 1. FRONTEND                                              │
│    Next.js 16 | React 19 | Tailwind CSS 4                │
│    (Security Dashboard, Triage Grid, Scan Logs)          │
└────────────────────────────┬─────────────────────────────┘
                             │  HTTP / REST
                             v
┌──────────────────────────────────────────────────────────┐
│ 2. BACKEND API                                           │
│    FastAPI | Python 3.11 | Uvicorn                       │
│    (Auth, Rate Limiting, Request Orchestration)          │
└────────────────────────────┬─────────────────────────────┘
                             │  Context & Prompts
                             v
┌──────────────────────────────────────────────────────────┐
│ 3. AI LAYER                                              │
│    Groq (LLaMA) | LangChain | ChromaDB (RAG)           │
│    (Contextual Analysis & Auto-Patch Generation)         │
└────────────────────────────┬─────────────────────────────┘
                             │  Enriched Rules & Probes
                             v
┌──────────────────────────────────────────────────────────┐
│ 4. SECURITY ENGINES                                      │
│    Semgrep (SAST) | Web Crawler | API Scanner            │
│    Supply Chain (SCA) | Docker Exploit Sandbox           │
└────────────────────────────┬─────────────────────────────┘
                             │  Scan Output & State
                             v
┌──────────────────────────────────────────────────────────┐
│ 5. DATABASE & STORAGE                                    │
│    PostgreSQL / SQLite | Vector Store                    │
│    (Findings, History, Security Knowledge Graph)         │
└────────────────────────────┬─────────────────────────────┘
                             │  Exports & Triggers
                             v
┌──────────────────────────────────────────────────────────┐
│ 6. EXTERNAL INTEGRATIONS                                 │
│    GitHub Security PRs | SARIF 2.1.0 | CI/CD Gates       │
│    (HTML/PDF/JSON Reports, Pipeline Annotations)         │
└──────────────────────────────────────────────────────────┘
```

## Database Design

The platform uses a hybrid multi-tier persistence architecture combining a relational database engine (SQLAlchemy ORM) with a vector embedding database for AI retrieval (RAG) and an on-demand graph data model.

### Entity-Relationship Schema Overview

```text
  +-----------------------------------+       1        N       +-----------------------------------+
  |               SCANS               |<-----------------------|             FINDINGS              |
  +-----------------------------------+                        +-----------------------------------+
  | PK  id: String(64)                |                        | PK  id: String(64)                |
  |     project_name: String(255)     |                        | FK  scan_id: String(64)           |
  |     scan_type: String(50)         |                        |     rule_id: String(255)          |
  |     status: String(50)            |                        |     severity: String(50)         |
  |     progress: Integer             |                        |     file_path: Text               |
  |     created_at: DateTime          |                        |     line_number: Integer          |
  |     completed_at: DateTime        |                        |     message: Text                 |
  |     source_url: Text              |                        |     cwe: String(100)              |
  |     summary_json: JSON            |                        |     owasp: String(100)            |
  |     timeline: JSON                |                        |     mitre: String(100)            |
  |     logs: JSON                    |                        |     status: String(50)            |
  +-----------------------------------+                        |     risk_score: Float             |
                                                               |     raw_payload_json: JSON        |
                                                               +-----------------------------------+
```

- **Graph Data Model**: Dynamically projects scan and finding records into a virtual Security Graph linking Repositories, Findings, Endpoints, and CWEs to find Attack Paths.
- **Vector Embeddings Store**: ChromaDB index storing embeddings for threat intelligence, security standards, and historical patches for RAG logic.
- **Optimization Strategy**: Indexes on query-heavy fields (`scan_id`, `severity`, `status`). Utilizes native `JSON` columns for flexible scanner payloads. SQLite is the default for local dev; PostgreSQL is for production.

## Technology Stack

### Backend
- Python 3.11+
- FastAPI, Uvicorn
- SQLAlchemy, Alembic (SQLite / PostgreSQL)
- Semgrep 1.38.0+
- GitPython, HTTPX
- Groq API (LLaMA models), LangChain, ChromaDB

### Frontend
- Next.js 16, React 19, TypeScript
- Tailwind CSS 4, TanStack React Query
- Recharts, Lucide icons

## Quick Start

### Prerequisites
- **Python**: 3.11 - 3.13
- **Node.js**: 18+
- **Git** & **Semgrep** (1.38.0+)
- **Docker** & **PostgreSQL** (Optional)

Install Semgrep:
```bash
pip install semgrep
semgrep --version
```

### Clone and Install
```bash
git clone https://github.com/Suresh-Nagvanshi/ai-appsec-platform.git
cd ai-appsec-platform
python -m venv .venv
# Windows PowerShell: .\.venv\Scripts\Activate.ps1
# Windows cmd: .venv\Scripts\activate.bat
pip install -r backend/requirements.txt
```

### Configure the Backend
Create a root `.env` file:
```env
GROQ_API_KEY=your_groq_api_key
API_KEY=replace_with_a_long_random_value
API_KEY_DISABLED=false
CORS_ORIGINS=http://localhost:3000
# DATABASE_URL=postgresql+psycopg2://appsec:appsec@localhost:5432/appsec
```

Start the backend:
```bash
python -m backend.run
```
- API: `http://127.0.0.1:8000`
- OpenAPI docs: `http://127.0.0.1:8000/docs`

### Configure and Start the Frontend
```bash
copy frontend\.env.local.example frontend\.env.local
cd frontend
npm install
npm run dev
```

Frontend URL: `http://localhost:3000`

## Configuration
- `GROQ_API_KEY`: Enables Groq-backed vulnerability analysis and fix generation.
- `API_KEY`: Protects application routers.
- `DATABASE_URL`: SQLAlchemy connection string (SQLite default).
- `GITHUB_TOKEN`: Allows automated branch, commit, and PR creation.
- `BACKEND_API_URL` & `BACKEND_API_KEY`: Frontend proxy config.

## API Surface
All routes (except `/health`) are protected by `X-API-Key`.
- **Scans**: `POST /api/scans/github`, `GET /api/scans/{scan_id}`
- **Findings**: `GET /findings`, `PATCH /findings/{finding_id}/status`
- **Security Graph**: `GET /api/security-graph`
- **Fixes**: `POST /api/fix/pull-request`
- **Integrations**: `GET /api/ci/sarif/{scan_id}`

## Frontend
The Next.js workspace provides an interactive dashboard, findings triage list, code context view, security graph visualization, and website scan history. It acts as a proxy forwarding requests to the FastAPI backend.

## Project Structure
```text
.
├── backend/
│   ├── main.py                         FastAPI application
│   ├── run.py                          Uvicorn launcher
│   ├── api/                            Feature APIs (Scans, Website, API, AI/ML, Supply Chain, Sandbox)
│   ├── ai/                             Model routing, prompts, RAG
│   ├── enrichment/                     Context & AST enrichment
│   ├── storage/                        Findings persistence
│   └── db/                             SQLAlchemy models, migrations
├── frontend/                           Next.js App Router workspace
├── data/                               Knowledge bases
├── database/                           Local SQLite db & state
└── results/                            Semgrep results
```

## Security Boundaries
- Backend routes are protected by explicit API Key verification.
- ZIP uploads enforce extraction safety limits.
- The Exploit Validation Sandbox runs in a highly restricted Docker container with dropped capabilities and read-only mounts.
- External probes (API, Website) reject local/private targets.

## Testing
Run the backend test suite:
```bash
python -m pytest -q
```
Run frontend lint and build:
```bash
npm --prefix frontend run lint
npm --prefix frontend run build
```

## Roadmap
- Production Dockerfiles and deployment smoke tests.
- RBAC, organizations, and tenant-isolated data access.
- GitHub App integration for workflow automation.
- GraphQL and Postman contract imports.

## Troubleshooting
- **Frontend backend errors**: Ensure `BACKEND_API_URL` and `BACKEND_API_KEY` are correct in `frontend/.env.local` and restart dev server.
- **Scans disappearing/restarting**: Run `python -m backend.run` instead of directly invoking `uvicorn --reload`, which restarts on temp file creation.
- **Exploit validation unavailable**: Ensure the Docker daemon is running locally.

## Contributing
1. Create a focused branch.
2. Add tests for behavioral changes.
3. Keep generated artifacts out of commits.
4. Use focused commit messages.

Maintained by **Suresh Nagvanshi**.
