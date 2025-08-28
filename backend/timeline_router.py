from fastapi import APIRouter, UploadFile, File
from fastapi.responses import JSONResponse
from schemas.models import Timeline
from agent_tools.parser import parse_logs
from agent_tools.enrich import enrich_events
from agent_tools.anomaly import apply_rules
from agent_tools.mitre_map_ibmrag import map_events_to_mitre
from agent_tools.timeline import build_timeline
from pathlib import Path
import json

router = APIRouter()

def _dump(m): 
    return m.model_dump() if hasattr(m, "model_dump") else m.dict()

@router.post("/timeline")
async def build(file: UploadFile = File(...)):
    """
    Upload a log file → parse, enrich, map to MITRE, and build a timeline.
    Returns the timeline as JSON.
    """
    text = (await file.read()).decode("utf-8", errors="ignore")
    events = parse_logs(text)
    events = enrich_events(events)
    events = apply_rules(events)
    events = map_events_to_mitre(events)
    tl: Timeline = build_timeline(events)
    return {"timeline": _dump(tl)}

@router.get("/timeline/latest")
def get_latest_timeline():
    """
    Get the most recently ingested timeline (from disk).
    Created automatically when /ingest is called.
    """
    p = Path(__file__).resolve().parents[1] / "data" / "out" / "timeline_latest.json"
    if not p.exists():
        return JSONResponse({"error": "no timeline yet"}, status_code=404)
    return json.loads(p.read_text(encoding="utf-8"))

@router.get("/graph/latest")
def get_latest_graph():
    """
    Get the most recently ingested graph (from disk).
    Created automatically when /ingest is called.
    """
    p = Path(__file__).resolve().parents[1] / "data" / "out" / "graph_latest.json"
    if not p.exists():
        return JSONResponse({"error": "no graph yet"}, status_code=404)
    return json.loads(p.read_text(encoding="utf-8"))
