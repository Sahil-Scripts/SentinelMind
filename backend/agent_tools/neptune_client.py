import os, requests

NEPTUNE_ENDPOINT = os.getenv("NEPTUNE_ENDPOINT")
NEPTUNE_PORT = os.getenv("NEPTUNE_PORT", "8182")
BASE = f"https://{NEPTUNE_ENDPOINT}:{NEPTUNE_PORT}/openCypher" if NEPTUNE_ENDPOINT else None

def _run(query: str):
    if not BASE:
        raise RuntimeError("NEPTUNE_ENDPOINT not set")
    r = requests.post(BASE, json={"query": query}, timeout=30, verify=False)
    r.raise_for_status()
    return r.json()

def graph_write(events):
    if not BASE:
        raise RuntimeError("NEPTUNE not configured")
    _run("BEGIN")
    try:
        for e in events:
            _run(f"MERGE (s:Node {{id:'{e.source}'}}) SET s.label='{e.source}'")
            _run(f"MERGE (t:Node {{id:'{e.target}'}}) SET t.label='{e.target}'")
            props = {
                "id": e.id, "stepNum": e.stepNum or 0, "time": e.time,
                "tactic": e.tactic or "", "technique": e.technique or "",
                "label": (e.summary or "")[:120]
            }
            prop_str = ", ".join([f"{k}:'{str(v)}'" for k,v in props.items()])
            _run(f"""
                MATCH (s:Node {{id:'{e.source}'}}),(t:Node {{id:'{e.target}'}})
                MERGE (s)-[r:STEP {{id:'{e.id}'}}]->(t)
                SET r+={{ {prop_str} }}
            """)
        _run("COMMIT")
    except Exception:
        _run("ROLLBACK")
        raise
    return graph_read()

def graph_read():
    if not BASE:
        raise RuntimeError("NEPTUNE not configured")
    N = _run("MATCH (n:Node) RETURN n.id as id, n.label as label")["results"][0]["data"]
    E = _run("MATCH (a:Node)-[r:STEP]->(b:Node) RETURN r.id as id,a.id,b.id,r.label,r.tactic,r.technique,r.stepNum ORDER BY r.stepNum")["results"][0]["data"]
    nodes = [{"id": n["row"][0], "label": n["row"][1]} for n in N]
    edges = [{"id": e["row"][0], "source": e["row"][1], "target": e["row"][2],
              "label": e["row"][3], "tactic": e["row"][4], "technique": e["row"][5], "stepNum": e["row"][6]} for e in E]
    return {"nodes": nodes, "edges": edges}
