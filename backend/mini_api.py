# backend/mini_api.py
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict, Any
import os, json

# ----- CORS so your Live Server (127.0.0.1:5500) can call us
app = FastAPI(title="SentinelMind Backend (Mini)")
app.add_middleware(
    CORSMiddleware,
    allow_origins=[
        "http://127.0.0.1:5500",
        "http://localhost:5500",
        "*",  # keep last; allow_credentials must be False when using "*"
    ],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)

GRAPH_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "graph_local.json")
GRAPH_PATH = os.path.abspath(GRAPH_PATH)

# ----- Models
class TimelineStep(BaseModel):
    step: int
    time: str
    actor: str
    target: str
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None

class TimelineIn(BaseModel):
    timeline: List[TimelineStep]
    iocs: Optional[List[Dict[str, Any]]] = None

class GraphOut(BaseModel):
    nodes: List[Dict[str, Any]]
    edges: List[Dict[str, Any]]

# ----- Helpers
def timeline_to_graph(timeline: List[TimelineStep]) -> GraphOut:
    # Build node set
    nodes = {}
    for s in timeline:
        nodes[s.actor] = {"id": s.actor, "label": "Actor"}
        nodes[s.target] = {"id": s.target, "label": "Asset"}
    # Build edges
    edges = []
    for s in timeline:
        edges.append({
            "source": s.actor,
            "target": s.target,
            "stepNum": s.step,
            "tactic": s.mitre_tactic or "Unknown",
            "technique": s.mitre_technique or "",
            "time": s.time,
            "description": s.description
        })
    return GraphOut(nodes=list(nodes.values()), edges=edges)

# ----- Routes

@app.get("/graph", response_model=GraphOut)
def get_graph():
    if not os.path.exists(GRAPH_PATH):
        # FastAPI would normally 404; return empty instead to be friendly
        return GraphOut(nodes=[], edges=[])
    with open(GRAPH_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)
    return GraphOut(**data)

@app.post("/graph-write")
def graph_write(body: TimelineIn):
    graph = timeline_to_graph(body.timeline)
    os.makedirs(os.path.dirname(GRAPH_PATH), exist_ok=True)
    with open(GRAPH_PATH, "w", encoding="utf-8") as f:
        json.dump(graph.dict(), f, ensure_ascii=False)
    return {"status": "ok", "stored": GRAPH_PATH}

# simple report generator using your safe template function
try:
    from .agent_tools.granite_report_ibm import generate_report_with_granite
except Exception:
    # ultra-safe inline fallback
    def generate_report_with_granite(timeline, iocs):
        rows = ""
        for s in timeline:
            rows += f"<tr><td>{s.step}</td><td>{s.time}</td><td>{s.actor}</td><td>{s.target}</td><td>{s.description}</td><td>{(s.mitre_tactic or '-')}/{(s.mitre_technique or '-')}</td></tr>"
        html = f"""<!doctype html><html><head><meta charset="utf-8"><title>ForensicMind Report</title>
        <style>body{{font-family:system-ui,Segoe UI,Roboto,sans-serif;margin:24px}} table{{width:100%;border-collapse:collapse}} th,td{{border-bottom:1px solid #eee;padding:8px;text-align:left}}</style>
        </head><body><h1>ForensicMind Report</h1>
        <h2>Timeline</h2><table><thead><tr><th>#</th><th>Time</th><th>Actor</th><th>Target</th><th>Description</th><th>MITRE</th></tr></thead><tbody>{rows}</tbody></table>
        </body></html>"""
        return html

@app.post("/report")
def report(body: TimelineIn):
    html = generate_report_with_granite([s.dict() for s in body.timeline], body.iocs or [])
    return {"html": html}

@app.get("/")
def root():
    return {"ok": True, "message": "Mini API running", "endpoints": ["/graph-write", "/graph", "/report"]}
