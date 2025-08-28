from typing import List, Optional
from pydantic import BaseModel

class Event(BaseModel):
    id: str
    time: str
    source: str
    target: str
    summary: str
    raw: dict = {}
    iocs: List[str] = []
    tactic: Optional[str] = None
    technique: Optional[str] = None
    stepNum: Optional[int] = None

class Timeline(BaseModel):
    events: List[Event]

class GraphNode(BaseModel):
    id: str
    label: Optional[str] = None
    tactic: Optional[str] = None
    technique: Optional[str] = None

class GraphEdge(BaseModel):
    id: str
    source: str
    target: str
    label: Optional[str] = ""
    tactic: Optional[str] = None
    technique: Optional[str] = None
    stepNum: int

class Graph(BaseModel):
    nodes: List[GraphNode]
    edges: List[GraphEdge]

# API payloads
class ReportRequest(BaseModel):
    timeline: Timeline
    iocs: List[str] = []

class ReportResponse(BaseModel):
    html: str

class NeptuneWriteRequest(BaseModel):
    # write by events (preferred); you can extend later to accept Graph
    events: List[Event]
