from fastapi import APIRouter, HTTPException
from schemas.models import NeptuneWriteRequest

router = APIRouter()

# Try to use your real Neptune client if present
try:
    from agent_tools.neptune_client import graph_write, graph_read  # type: ignore
    _has_neptune = True
except Exception as _e:
    _has_neptune = False
    _memory_graph = {"nodes": [], "edges": []}
    def graph_write(events):
        # very small in-memory demo graph
        nodes = {}
        edges = []
        for e in events:
            nodes[e.source] = {"id": e.source, "label": e.source}
            nodes[e.target] = {"id": e.target, "label": e.target}
            edges.append({
                "id": e.id, "source": e.source, "target": e.target,
                "label": (e.summary or "")[:120],
                "tactic": e.tactic, "technique": e.technique,
                "stepNum": e.stepNum or 0
            })
        _memory_graph["nodes"] = list(nodes.values())
        _memory_graph["edges"] = edges
        return _memory_graph
    def graph_read():
        return _memory_graph

@router.post("/neptune/graph-write")
def neptune_write(req: NeptuneWriteRequest):
    if not req.events:
        raise HTTPException(status_code=400, detail="No events provided")
    g = graph_write(req.events)
    return g

@router.get("/neptune/graph-read")
def neptune_read():
    return graph_read()
