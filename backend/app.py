from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

app = FastAPI(title="SentinelMind API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

@app.get("/health")
def health():
    return {"ok": True}

@app.get("/graph")
def graph():
    return {
        "nodes": [
            {"id": "hostA", "label": "Web Server"},
            {"id": "db01", "label": "Database"},
            {"id": "adminPC", "label": "Admin PC"},
            {"id": "fw01", "label": "Firewall"},
            {"id": "mail01", "label": "Mail Server"},
            {"id": "hrPC", "label": "HR Laptop"},
            {"id": "filesrv", "label": "File Server"},
            {"id": "devPC", "label": "Dev Workstation"},
            {"id": "backup01", "label": "Backup Server"},
            {"id": "dmz01", "label": "DMZ Gateway"}
        ],
        "edges": [
            {"id": "e1", "source": "hostA", "target": "db01", "stepNum": 1, "tactic": "Credential Access", "technique": "T1110"},
            {"id": "e2", "source": "hostA", "target": "fw01", "stepNum": 2, "tactic": "Lateral Movement", "technique": "T1021"},
            {"id": "e3", "source": "fw01", "target": "adminPC", "stepNum": 3, "tactic": "Credential Access", "technique": "T1552"},
            {"id": "e4", "source": "adminPC", "target": "mail01", "stepNum": 4, "tactic": "Exfiltration", "technique": "T1041"},
            {"id": "e5", "source": "hrPC", "target": "filesrv", "stepNum": 5, "tactic": "Credential Access", "technique": "T1003"},
            {"id": "e6", "source": "filesrv", "target": "db01", "stepNum": 6, "tactic": "Lateral Movement", "technique": "T1021"},
            {"id": "e7", "source": "db01", "target": "backup01", "stepNum": 7, "tactic": "Exfiltration", "technique": "T1048"},
            {"id": "e8", "source": "devPC", "target": "dmz01", "stepNum": 8, "tactic": "Credential Access", "technique": "T1110"},
            {"id": "e9", "source": "dmz01", "target": "hostA", "stepNum": 9, "tactic": "Lateral Movement", "technique": "T1021"},
            {"id": "e10", "source": "adminPC", "target": "backup01", "stepNum": 10, "tactic": "Exfiltration", "technique": "T1041"},
            {"id": "e11", "source": "hrPC", "target": "mail01", "stepNum": 11, "tactic": "Credential Access", "technique": "T1110"},
            {"id": "e12", "source": "devPC", "target": "filesrv", "stepNum": 12, "tactic": "Lateral Movement", "technique": "T1021"},
            {"id": "e13", "source": "filesrv", "target": "dmz01", "stepNum": 13, "tactic": "Exfiltration", "technique": "T1048"},
            {"id": "e14", "source": "hostA", "target": "hrPC", "stepNum": 14, "tactic": "Discovery", "technique": "T1087"},
            {"id": "e15", "source": "mail01", "target": "db01", "stepNum": 15, "tactic": "Persistence", "technique": "T1098"}
        ]
    }


# Routers (each wrapped to avoid whole-app crashes if a file is missing)
try:
    from ingest_router import router as ingest_router
    app.include_router(ingest_router)
    print("[app] ingest_router loaded")
except Exception as e:
    print("[app] WARN: ingest_router not loaded ->", e)

try:
    from timeline_router import router as timeline_router
    app.include_router(timeline_router)
    print("[app] timeline_router loaded")
except Exception as e:
    print("[app] WARN: timeline_router not loaded ->", e)

try:
    from report_router import router as report_router
    app.include_router(report_router)
    print("[app] report_router loaded")
except Exception as e:
    print("[app] WARN: report_router not loaded ->", e)

try:
    from neptune_router import router as neptune_router
    app.include_router(neptune_router)
    print("[app] neptune_router loaded")
except Exception as e:
    print("[app] WARN: neptune_router not loaded ->", e)
