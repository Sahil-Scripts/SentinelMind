from fastapi import APIRouter, HTTPException
from fastapi.responses import HTMLResponse
from schemas.models import ReportRequest, ReportResponse, Timeline
from pathlib import Path
import json

# Granite / fallback report generator
from agent_tools.granite_report_ibm import generate_report_html

router = APIRouter()

def _dump(m): 
    return m.model_dump() if hasattr(m, "model_dump") else m.dict()

@router.post("/report", response_model=ReportResponse)
def make_report(req: ReportRequest):
    """Generate a report from a timeline + IOCs."""
    html = generate_report_html(req.timeline, req.iocs)
    return {"html": html}

@router.get("/report/html-latest")
def report_html_latest():
    """Generate a report using the latest ingested timeline (saved on disk)."""
    p = Path(__file__).resolve().parents[1] / "data" / "out" / "timeline_latest.json"
    if not p.exists():
        raise HTTPException(404, "No timeline_latest.json; call /ingest first.")
    
    data = json.loads(p.read_text(encoding="utf-8"))
    tl = Timeline(**data)
    html = generate_report_html(tl, [])
    return HTMLResponse(content=html, status_code=200)
