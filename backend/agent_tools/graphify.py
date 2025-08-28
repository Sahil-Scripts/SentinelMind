try:
    from schemas.models import Timeline, Graph, GraphNode, GraphEdge
except Exception:
    from backend.schemas.models import Timeline, Graph, GraphNode, GraphEdge  # type: ignore

def timeline_to_graph(tl: Timeline) -> Graph:
    node_ids = set()
    nodes = []
    edges = []
    for e in tl.events:
        if e.source not in node_ids:
            node_ids.add(e.source)
            nodes.append(GraphNode(id=e.source, label=e.source))
        if e.target not in node_ids:
            node_ids.add(e.target)
            nodes.append(GraphNode(id=e.target, label=e.target))
        edges.append(GraphEdge(
            id=e.id,
            source=e.source,
            target=e.target,
            label=(e.summary or "")[:120],
            tactic=e.tactic,
            technique=e.technique,
            stepNum=e.stepNum or 0
        ))
    return Graph(nodes=nodes, edges=edges)
