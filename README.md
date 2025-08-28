# SentinelMind (48h Hackathon)

AI-powered cyber investigation: turns messy logs into a clean **ForensicMind** report (IBM Granite) and an animated **SentinelVision** attack replay (AWS Neptune).

## Services (explicit)
- **IBM Granite (watsonx.ai)** – report writer
- **IBM RAG (watsonx Retrieval Augmented Generation)** – MITRE mapping
- **AWS Bedrock Agents** – orchestration
- **AWS Neptune** – graph DB for attack paths

## Quickstart

```bash
# 1) Python env
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# 2) Environment (copy and edit)
cp .env.example .env

# 3) Run backend
uvicorn backend.app:app --reload

# 4) Open SentinelVision
#    (served as static HTML; open file or serve via any server)
#    frontend/sentinelvision/index.html
```

## Endpoints (FastAPI)
- `POST /parse`        → { events }
- `POST /enrich`       → { events }
- `POST /mitre-map`    → { events }         # uses **IBM RAG**
- `POST /timeline`     → { timeline }
- `POST /report`       → { html }           # uses **IBM Granite**
- `POST /graph-write`  → { ok }             # writes to **AWS Neptune**
- `GET  /graph`        → { nodes, edges }   # reads from **AWS Neptune** (fallback to local)

## Bedrock Agent
See `bedrock/agent.json` for a minimal agent definition using HTTPS action groups pointing to the above endpoints.

> Note: The code includes graceful fallbacks if credentials are missing, so you can demo locally and then switch on IBM/AWS with environment variables.
