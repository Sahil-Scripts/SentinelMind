from fastapi import APIRouter, UploadFile, File

from schemas.models import Timeline
from agent_tools.parser import parse_logs
from agent_tools.enrich import enrich_events
from agent_tools.anomaly import apply_rules
from agent_tools.mitre_map_ibmrag import map_events_to_mitre
from agent_tools.timeline import build_timeline
from agent_tools.graphify import timeline_to_graph

router = APIRouter()

def _dump(model):
    return model.model_dump() if hasattr(model, "model_dump") else model.dict()

@router.post("/ingest")
async def ingest(file: UploadFile = File(...)):
    text = (await file.read()).decode("utf-8", errors="ignore")
    events = parse_logs(text)
    events = enrich_events(events)
    events = apply_rules(events)
    events = map_events_to_mitre(events)
    tl: Timeline = build_timeline(events)
    graph = timeline_to_graph(tl)
    return {"timeline": _dump(tl), "graph": _dump(graph)}
