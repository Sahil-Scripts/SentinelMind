from pydantic import BaseModel, Field
from typing import List, Optional

class Event(BaseModel):
    time: str
    src_ip: Optional[str] = None
    dst_ip: Optional[str] = None
    actor: Optional[str] = None
    target: Optional[str] = None
    message: str
    tags: List[str] = Field(default_factory=list)
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
    step: Optional[int] = None

class TimelineStep(BaseModel):
    step: int
    time: str
    actor: str
    target: str
    description: str
    mitre_tactic: Optional[str] = None
    mitre_technique: Optional[str] = None
