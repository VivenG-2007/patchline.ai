# HackWave AI (Patchline)

AI-reviewed vulnerability scanning with human-approved, tested pull requests. **1 Next.js frontend + 3 independent microservices**, wired together with JWT auth, Redis, Supabase, MongoDB, and Azure Blob Storage — fully configured for **Render.com** deployment.

```
Render Web App (frontend) ──► main-service (Render Web Service: Supabase + Redis)
                                    │                           │
                                    ▼                           ▼
                         auth_services (Render)   ai-service (Render: FastAPI + Featherless)
                         (Issues RS256 JWTs)      (SAST Scanner & Model Router Engine)
```

---

## 1. Architecture Overview

| Service | Tech Stack | Role | Render Deployment Type |
|---|---|---|---|
| [`frontend/`](file:///c:/Users/viven/Desktop/patchline/frontend) | Next.js 16, React 19, TypeScript, Tailwind v4 | Login/register UI, dashboard, vulnerability scanner console | **Render Web Service** (Node) / Vercel |
| [`services/auth_services/`](file:///c:/Users/viven/Desktop/patchline/services/auth_services) | Node.js / Express, MongoDB, Redis | User authentication, issues RS256 signed JWTs | **Render Web Service** (Node) |
| [`services/main_services/`](file:///c:/Users/viven/Desktop/patchline/services/main_services) | Node.js / Express, Supabase, Redis | Core product API, gateway to AI service, GitHub/Jira OAuth integrations | **Render Web Service** (Node) |
| [`services/ai_services/`](file:///c:/Users/viven/Desktop/patchline/services/ai_services) | Python / FastAPI, MongoDB, Redis, Azure Blob, Elasticsearch | SAST scanning engine (Semgrep + Tree-sitter + Regex), Model Router, RAG memory | **Render Web Service** (Python / Docker) |

> [!NOTE]
> **Core Authentication Design:** `services/auth_services` signs JWT tokens using an RS256 private key (`JWT_PRIVATE_KEY_BASE64`). `services/main_services` and `services/ai_services` hold only the matching public key (`JWT_PUBLIC_KEY_BASE64`) and verify every incoming JWT locally — eliminating network latency back to `auth_services` on API calls.

---

## 2. AI Model Router Matrix (`model_router.py`)

All AI calls route through `model_router.py` using **Featherless AI (Primary)** with **OpenAI / Azure OpenAI (Fallback)**:

| Task Key | Role / Purpose | Primary Model (Featherless) | Fallback Model (OpenAI / Azure) | Applied Location |
|---|---|---|---|---|
| `analysis` | Supplementary SAST & finding enrichment | `Qwen3-Coder-30B-A3B` | `gpt-4.1-mini` | `scanner.py` |
| `rag_ranking` | Prior-art candidate ranking | `DeepSeek-V4-Flash` | `gpt-5.2` | Reserved for candidate ranking |
| `fix` | Vulnerability patch generation | `Qwen3-Coder-480B-A35B` | `gpt-5.2` | `scanner.py` (`_generate_fix`) |
| `verify` | Independent adversarial patch review | `DeepSeek-V4-Pro` | `gpt-5.3-codex` | `scanner.py` (`_codex_review_fix`) |
| `general` | Free-form chat & analysis API | `Qwen3-Coder-30B-A3B` | `gpt-4.1-mini` | `ai_service.py` (`/api/ai/*`) |

---

## 3. Repository Structure

```
patchline/
├── frontend/                  # Next.js 16 Web Application
├── services/
│   ├── auth_services/         # Authentication Service (Deploys on Render)
│   ├── main_services/         # Core API & Gateway Service (Deploys on Render)
│   └── ai_services/           # SAST Scanner & AI Generation Engine (Deploys on Render)
├── docs/                      # Comprehensive technical documentation & AI specs
├── render.yaml                # Render Blueprint infrastructure specification
└── README.md
```

---

## 4. Deploying to Render (Render.com)

You can deploy the entire HackWave AI architecture to Render using either **Automated Blueprint Deployment** (Recommended) or **Manual Web Service Setup**.

### Method A: Automated Deployment via Render Blueprint (`render.yaml`)

1. Push this repository to your GitHub or GitLab account.
2. Log into your [Render Dashboard](https://dashboard.render.com/).
3. Click **New +** → **Blueprint**.
4. Connect your repository. Render will automatically detect [`render.yaml`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/render.yaml) and create the 4 Web Services:
   - `hackwave-auth-service`
   - `hackwave-main-service`
   - `hackwave-ai-service`
   - `hackwave-frontend`
5. In the Render Dashboard, fill in the secret environment variables (`MONGODB_URI`, `REDIS_URL`, `SUPABASE_URL`, `JWT_PRIVATE_KEY_BASE64`, `JWT_PUBLIC_KEY_BASE64`, `FEATHERLESS_API_KEY`) under each service's **Environment** tab.
6. Click **Apply** to trigger simultaneous automated builds.

---

### Method B: Manual Web Service Deployment on Render

If creating services manually in the Render UI:

#### 1. Auth Service (`services/auth_services`)
- **Service Type:** Web Service
- **Environment:** Node
- **Root Directory:** `services/auth_services`
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Health Check Path:** `/health`
- **Required Environment Variables:**
  - `PORT`: `10000` (or leave default `$PORT`)
  - `NODE_ENV`: `production`
  - `MONGODB_URI`: `mongodb+srv://...`
  - `REDIS_URL`: `rediss://...`
  - `JWT_PRIVATE_KEY_BASE64`: `<base64-encoded-rs256-private-key>`
  - `JWT_PUBLIC_KEY_BASE64`: `<base64-encoded-rs256-public-key>`
  - `CORS_ORIGINS`: `https://hackwave-frontend.onrender.com`

#### 2. Main Service (`services/main_services`)
- **Service Type:** Web Service
- **Environment:** Node
- **Root Directory:** `services/main_services`
- **Build Command:** `npm install`
- **Start Command:** `npm start`
- **Health Check Path:** `/health`
- **Required Environment Variables:**
  - `PORT`: `10000`
  - `SUPABASE_URL`: `https://your-project.supabase.co`
  - `SUPABASE_KEY`: `<your-supabase-anon-or-service-role-key>`
  - `REDIS_URL`: `rediss://...`
  - `JWT_PUBLIC_KEY_BASE64`: `<base64-encoded-rs256-public-key>`
  - `AUTH_SERVICE_URL`: `https://hackwave-auth-service.onrender.com`
  - `AI_SERVICE_URL`: `https://hackwave-ai-service.onrender.com`

#### 3. AI Scanning Service (`services/ai_services`)
- **Service Type:** Web Service
- **Environment:** Python 3 (or Docker)
- **Root Directory:** `services/ai_services`
- **Build Command:** `pip install -r requirements.txt`
- **Start Command:** `uvicorn main:app --host 0.0.0.0 --port $PORT`
- **Health Check Path:** `/docs`
- **Required Environment Variables:**
  - `PORT`: `10000`
  - `MONGO_URI`: `mongodb+srv://...`
  - `REDIS_URL`: `rediss://...`
  - `FEATHERLESS_ENABLED`: `true`
  - `FEATHERLESS_API_KEY`: `<your-featherless-api-key>`
  - `AZURE_STORAGE_CONNECTION_STRING`: `<azure-blob-connection-string>`
  - `ELASTICSEARCH_URL`: `https://...`
  - `JWT_PUBLIC_KEY_BASE64`: `<base64-encoded-rs256-public-key>`

#### 4. Frontend Web App (`frontend`)
- **Service Type:** Web Service
- **Environment:** Node
- **Root Directory:** `frontend`
- **Build Command:** `npm install && npm run build`
- **Start Command:** `npm run start`
- **Health Check Path:** `/`
- **Required Environment Variables:**
  - `PORT`: `10000`
  - `NEXT_PUBLIC_API_URL`: `https://hackwave-main-service.onrender.com`
  - `NEXT_PUBLIC_AUTH_URL`: `https://hackwave-auth-service.onrender.com`

---

## 5. Local Development Setup

**Prerequisites:** Node.js (v18+), Python (v3.10+), Docker (optional for databases).

```bash
# 1. Clone repository
git clone https://github.com/25r11a05bd-spec/hackwave.ai.git
cd hackwave.ai

# 2. Install dependencies across all projects
npm run install:all

# 3. Generate RS256 Auth Keypair
cd services/auth_services && npm run generate-keys
```

### Running Services

```bash
# Option A: Run locally with Docker Compose
docker compose up --build

# Option B: Run locally in dev mode
npm run dev
```

Local Endpoint Access:
- **Frontend UI:** `http://localhost:3000`
- **Auth Service:** `http://localhost:5000`
- **Main API Service:** `http://localhost:5001`
- **AI Scanning Engine:** `http://localhost:5002` (Docs: `http://localhost:5002/docs`)

---

## 6. Environment Variables Reference

| Variable Name | Description | Used By Service |
|---|---|---|
| `PORT` | Web server listening port (Render provides automatically via `$PORT`) | All Services |
| `JWT_PRIVATE_KEY_BASE64` | Base64-encoded RS256 Private Key for token signing | `services/auth_services` |
| `JWT_PUBLIC_KEY_BASE64` | Base64-encoded RS256 Public Key for JWT verification | `auth_services`, `main`, `ai-service` |
| `MONGODB_URI` | MongoDB connection string | `auth_services`, `ai-service` |
| `REDIS_URL` | Redis connection URL for queues & caching | `auth_services`, `main`, `ai-service` |
| `SUPABASE_URL` | Supabase project URL | `services/main` |
| `SUPABASE_KEY` | Supabase API Key | `services/main` |
| `FEATHERLESS_API_KEY` | Primary Featherless AI key | `services/ai-service` |
| `AUTH_SERVICE_URL` | Render URL of auth service | `main`, `frontend` |
| `AI_SERVICE_URL` | Render URL of AI service | `main` |
| `NEXT_PUBLIC_API_URL` | Render URL of main service | `frontend` |

---

## 7. Documentation Suite

- 🤖 [`docs/AI_CONTEXT.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/AI_CONTEXT.md) — Machine-readable specification for AI models & LLMs.
- 🧠 [`docs/ai-routing.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/ai-routing.md) — Centralized Model Router specification (Featherless AI + Fallback).
- 🔄 [`docs/ai-pipeline.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/ai-pipeline.md) — 8-stage scan-to-fix pipeline specification.
- 🏗️ [`docs/architecture.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/architecture.md) — Architectural overview, microservice separation, and Redis topology.
- 🔌 [`docs/api.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/api.md) — Comprehensive REST & WebSocket API reference.
- 🔒 [`docs/security.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/security.md) — Security model, RS256 JWT key rotation, and OAuth controls.
- 🚀 [`docs/deployment.md`](file:///c:/Users/hp/Desktop/hackwave%201th/hackwave.ai/docs/deployment.md) — Render.com deployment guide & infrastructure setup.
