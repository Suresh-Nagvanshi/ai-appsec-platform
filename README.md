# AI AppSec Platform

AI-powered Application Security (AppSec) platform designed to combine traditional security scanning with contextual AI reasoning for vulnerability prioritization, exploitability analysis, and remediation guidance.

---

## Vision

Traditional security tools often generate large volumes of findings:

- False positives
- Duplicate issues
- Low-priority alerts
- Difficult remediation paths

The goal of this platform is to transform raw scanner outputs into:

- Contextual findings
- Exploitability-aware analysis
- AI-assisted remediation
- Actionable security intelligence

The long-term objective is to function as an AI-assisted security engineer rather than a simple scanner.

---

## Core Objectives

- Reduce alert fatigue
- Improve vulnerability prioritization
- Provide AI-generated contextual reasoning
- Support secure multi-tenant architecture
- Enable repository, web application, API, and AI/ML security testing
- Build an enterprise-grade AppSec workflow platform

---

## Current Architecture

```text
Repository / ZIP Upload / GitHub URL / Website URL
                        ↓
                Security Scanner Layer
                        ↓
              Findings Normalization
                        ↓
              Context Enrichment Layer
            ├── Framework Detection
            ├── Endpoint Extraction
            ├── Snippet Extraction
            └── Context Builder
                        ↓
                 Risk Scoring Engine
                        ↓
                  AI Analysis Layer
            ├── Prompt Builder
            ├── Model Router
            ├── Response Parser
            └── Analysis Engine
                        ↓
               Deduplication Layer
                        ↓
                Findings Repository
                        ↓
                  Reporting Layer
                        ↓
          Dashboard / APIs / Reports
```

---

## Technology Stack

### Backend

- Python
- FastAPI
- Groq API
- JSON storage (temporary)

Future:

- PostgreSQL
- Docker
- Prisma ORM

### Frontend

- Next.js
- TypeScript
- Tailwind CSS
- React Query

### AI / Security

- Semgrep
- OWASP references
- MITRE ATT&CK mappings
- CVE datasets
- AI reasoning engine

---

## Current Project Status

**Current Phase**

Foundation + AI analysis infrastructure + frontend dashboard architecture

**Status**

Actively under development

---

## Implemented Features

### AI Layer

- Prompt Builder
- Response Parser
- Analysis Engine
- Async Analysis Engine
- Batch Analysis Engine
- Model Router

### Context Enrichment

- Framework Detection
- Endpoint Extraction
- Snippet Extraction
- Context Builder

### Security Processing

- Risk Scoring
- Finding Deduplication
- Findings Repository
- Diff Analyzer
- Report Generation

### Backend

- FastAPI application
- Findings API endpoint
- Scan storage architecture

### Frontend

- Dashboard UI
- Findings workflow interface
- Security posture visualization
- React Query integration
- Backend integration

---

## In Progress

- PostgreSQL integration
- Docker setup
- Authentication
- RBAC
- Multi-tenant isolation

---

## Planned Features

### Repository Security

- GitHub repository URL scanner
- ZIP upload scanner enhancements
- Branch selection
- Incremental scanning

### Website Security

- Website URL scanner
- Crawling engine
- Page discovery
- Client-side vulnerability analysis

### API Security

- Endpoint discovery
- API endpoint tester
- Authentication testing
- Authorization testing
- OWASP API Top 10 mapping

### AI/ML Security Testing

- Prompt injection testing
- Jailbreak testing
- Hallucination detection
- Model behavior evaluation
- Safety assessment
- Adversarial testing

### Intelligence Layer

- Optional anonymized telemetry
- RAG-based security knowledge system
- Similar vulnerability detection

### Enterprise Features

- Organization support
- Team management
- RBAC
- Audit logs
- CI/CD integrations
- Webhooks

---

## Multi-Tenant Security Principles

- Tenant isolation
- Organization-level access control
- RBAC
- Data segregation
- Secure storage practices

---

## Privacy Principles

Customer source code and security findings are sensitive.

Planned approach:

> Customers may optionally allow anonymized security telemetry to improve detection quality and AI reasoning.

Important constraints:

- Optional
- Anonymized
- Telemetry only
- No raw code sharing

---

## Future Roadmap

### Phase 1

- Core scanning pipeline
- AI analysis engine
- Dashboard foundation

### Phase 2

- Repository scanning
- Website scanning
- API security testing

### Phase 3

- AI/ML security testing

### Phase 4

- Enterprise deployment
- RBAC
- Multi-tenancy
- CI/CD integrations

---

## Local Setup

### Clone Repository

```bash
git clone https://github.com/<username>/ai-appsec-platform.git
cd ai-appsec-platform
```

### Backend

```bash
pip install -r requirements.txt
uvicorn backend.main:app --reload
```

### Frontend

```bash
cd frontend
npm install
npm run dev
```

Frontend:

```text
http://localhost:3000
```

Backend:

```text
http://127.0.0.1:8000
```

---

## Contributors

Maintained by:

**Suresh Nagvanshi**