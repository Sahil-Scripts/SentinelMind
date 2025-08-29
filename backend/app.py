from fastapi import FastAPI, Query, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging
from pathlib import Path
import json
from typing import Dict, List, Any, Optional, Tuple
from pydantic import BaseModel
from datetime import datetime
import re
import os

# ================================
# IBM watsonx.ai / Granite (version-safe)
# ================================
WX_AVAILABLE = True
WX_IMPORT_ERR: Optional[Exception] = None
WX_MODE = None  # "model" or "model_inference"

try:
    # Preferred (modern) SDK path
    from ibm_watsonx_ai import Credentials
    from ibm_watsonx_ai.foundation_models import Model  # modern entry point
    WX_MODE = "model"
except Exception as _e1:
    try:
        # Fallback for older SDKs that exposed ModelInference
        from ibm_watsonx_ai import Credentials, ModelInference
        WX_MODE = "model_inference"
    except Exception as _e2:
        WX_AVAILABLE = False
        WX_IMPORT_ERR = _e1 or _e2

WATSONX_API_KEY    = os.getenv("WATSONX_API_KEY", "")
WATSONX_PROJECT_ID = os.getenv("WATSONX_PROJECT_ID", "")
# Default to EU-GB per your values (override via env if needed)
WATSONX_BASE_URL   = os.getenv("WATSONX_BASE_URL", "https://eu-gb.ml.cloud.ibm.com")
# Common Granite chat model (override if your account uses a different ID)
WATSONX_MODEL_ID   = os.getenv("WATSONX_MODEL_ID", "ibm/granite-13b-chat-v2")

def _wx_is_configured() -> bool:
    return WX_AVAILABLE and bool(WATSONX_API_KEY and WATSONX_PROJECT_ID)

def _wx_generate(prompt: str, model_id: Optional[str] = None) -> str:
    """Generate text with Granite across SDK variants; returns text or an error marker."""
    if not _wx_is_configured():
        if not WX_AVAILABLE:
            return f"(Granite disabled: SDK not available: {WX_IMPORT_ERR})"
        return "(Granite disabled: missing API key/project id)"

    try:
        creds = Credentials(api_key=WATSONX_API_KEY, url=WATSONX_BASE_URL)
        mdl_id = model_id or WATSONX_MODEL_ID

        if WX_MODE == "model":
            model = Model(
                model_id=mdl_id,
                credentials=creds,
                project_id=WATSONX_PROJECT_ID,
                params={
                    "decoding_method": "greedy",
                    "max_new_tokens": 600,
                    "temperature": 0.2,
                },
            )
            out = model.generate_text(prompt=prompt) if hasattr(model, "generate_text") else model.generate(prompt=prompt)
            if isinstance(out, dict):
                res = out.get("results") or []
                if isinstance(res, list) and res and isinstance(res[0], dict):
                    return res[0].get("generated_text") or res[0].get("text") or ""
                return out.get("generated_text", "")
            return str(out)

        elif WX_MODE == "model_inference":
            mi = ModelInference(
                model_id=mdl_id,
                credentials=creds,
                project_id=WATSONX_PROJECT_ID,
                params={
                    "decoding_method": "greedy",
                    "max_new_tokens": 600,
                    "temperature": 0.2,
                },
            )
            out = mi.generate_text(prompt=prompt)
            if isinstance(out, dict):
                res = out.get("results") or []
                if isinstance(res, list) and res and isinstance(res[0], dict):
                    return res[0].get("generated_text") or res[0].get("text") or ""
                return out.get("generated_text", "")
            return str(out)

        else:
            return "(Granite disabled: unknown SDK mode)"

    except Exception as e:
        return f"(Granite generation failed: {e})"

def _build_prompts_for_report(
    timeline: List[Dict[str, Any]],
    iocs: List[Dict[str, Any]],
    mitre: List[Dict[str, Any]],
) -> Dict[str, str]:
    """Create concise prompts for 'easy' and 'soc' summaries."""
    tl_lines: List[str] = []
    for t in timeline[:300]:
        ts = t.get("timestamp", "")
        idx = t.get("idx", "")
        s = t.get("summary", "")
        tl_lines.append(f"[{idx}] {ts} :: {s}")

    ioc_lines = [f"{i.get('type','')}={i.get('value','')} (evt#{i.get('event_idx','')})" for i in iocs[:200]]

    mitre_lines: List[str] = []
    for m in mitre[:200]:
        ids = ", ".join([x.get("id", "") for x in (m.get("techniques") or []) if x.get("id")])
        if ids:
            mitre_lines.append(f"evt#{m.get('event_idx','')}: {ids}")

    timeline_blob = "\n".join(tl_lines)
    iocs_blob     = "\n".join(ioc_lines)
    mitre_blob    = "\n".join(mitre_lines)

    easy_prompt = f"""
You are a helpful cybersecurity assistant. Write a SHORT, easy-to-read summary for a non-technical user based on the logs below.
- Explain in plain words what we saw (no jargon).
- Give 3-6 clear action steps and a few practical safety tips.
- Avoid panic; be calm and factual.

TIMELINE (idx, time, summary):
{timeline_blob}

IOCS (type=value evt#):
{iocs_blob}

MITRE (evt#: IDs):
{mitre_blob}

Return only prose paragraphs and bullet points. Keep it under 250 words.
""".strip()

    soc_prompt = f"""
You are a senior SOC analyst. Produce a concise but dense incident note with:
- Executive 2-sentence summary
- Observed MITRE techniques (IDs → tactic name), with counts
- Key artifacts / IOCs
- Attack path hypotheses with backtracking anchors (use evt# indices), oldest→newest, cite events like [#12→#18→#21]
- Immediate containment + next steps

Be precise. Prefer concrete references (“evt#17: powershell.exe …”). No fluff.

TIMELINE (idx, time, summary):
{timeline_blob}

IOCS:
{iocs_blob}

MITRE per-event:
{mitre_blob}

Return markdown with headings.
""".strip()

    return {"easy": easy_prompt, "soc": soc_prompt}


# ================================
# FastAPI app
# ================================
app = FastAPI(title="SentinelMind API")

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], allow_credentials=True,
    allow_methods=["*"], allow_headers=["*"]
)

# Data locations / constants
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "data"            # put your logs here (next to app.py)
DATA_DIR.mkdir(exist_ok=True)

LOG_TYPES = ("application", "system", "network")
LOG_FILE_MAP = {
    "application": DATA_DIR / "application.log",
    "system":     DATA_DIR / "system.log",
    "network":    DATA_DIR / "network.log",
}

# ================================
# Helpers: read & build graph
# ================================
def _read_jsonl(path: Path) -> List[Dict[str, Any]]:
    """Read JSON Lines file safely (skips blank/comment/malformed lines)."""
    events: List[Dict[str, Any]] = []
    if not path.exists():
        return events
    with path.open("r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                obj = json.loads(line)
                if isinstance(obj, dict):
                    events.append(obj)
            except json.JSONDecodeError:
                continue
    return events

def _build_graph_from_events(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """
    Convert event dicts to nodes/edges.
    Expected per-event fields:
      source, target (required)
      tactic, technique, stepNum (optional)
      source_label, target_label (optional node labels)
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Dict[str, Any]] = []
    step = 1

    for ev in events:
        s = ev.get("source")
        t = ev.get("target")
        if not s or not t:
            continue

        nodes.setdefault(s, {"id": s, "label": ev.get("source_label", s)})
        nodes.setdefault(t, {"id": t, "label": ev.get("target_label", t)})

        edges.append({
            "id": ev.get("id", f"e{step}"),
            "source": s,
            "target": t,
            "stepNum": int(ev.get("stepNum", step)),
            "tactic": ev.get("tactic", "Unknown"),
            "technique": ev.get("technique", "T0000"),
        })
        step += 1

    return {"nodes": list(nodes.values()), "edges": edges}

def _fallback_sample_graph() -> Dict[str, Any]:
    # Renders even if logs are empty/missing
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
            {"id": "dmz01", "label": "DMZ Gateway"},
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
            {"id": "e15", "source": "mail01", "target": "db01", "stepNum": 15, "tactic": "Persistence", "technique": "T1098"},
        ],
    }

# ================================
# ForensicMind pipeline
# ================================
MAX_SUMMARY_LEN = 240          # characters kept in timeline/exec views
MAX_DETAILS_LEN = 12000        # hard cap to avoid megabyte pastes
ELLIPSIS = " … [truncated]"

def single_line(s: str) -> str:
    """Collapse whitespace/newlines into a single line."""
    if not s:
        return ""
    return re.sub(r"\s+", " ", s.strip())

def shorten(s: str, n: int = MAX_SUMMARY_LEN) -> Tuple[str, bool]:
    """Return (short_text, was_truncated)."""
    if not s:
        return "", False
    if len(s) > n:
        return s[:n].rstrip() + ELLIPSIS, True
    return s, False

class FMLogsIn(BaseModel):
    logs: str

class FMEventsIn(BaseModel):
    events: List[Dict[str, Any]]

def fm_parse_lines(logs: str) -> List[Dict[str, Any]]:
    """Split pasted text logs into event dicts. Extracts an ISO-ish timestamp if present."""
    events: List[Dict[str, Any]] = []
    for i, line in enumerate(l for l in logs.splitlines() if l.strip()):
        ts = None
        m = re.search(r'(\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2})', line)
        if m:
            ts = m.group(1)
        raw = line.strip()
        if len(raw) > MAX_DETAILS_LEN:
            raw = raw[:MAX_DETAILS_LEN] + ELLIPSIS
        events.append({
            "idx": i,
            "raw": raw,
            "timestamp": ts or datetime.utcnow().isoformat(),
            "source": "stdin",
        })
    return events

def fm_enrich(events: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Very light IOC extraction (IP, domain)."""
    iocs: List[Dict[str, Any]] = []
    for e in events:
        raw = e.get("raw", "")
        for ip in re.findall(r'\b\d{1,3}(?:\.\d{1,3}){3}\b', raw):
            iocs.append({"type": "ip", "value": ip, "event_idx": e["idx"]})
        for dom in re.findall(r'\b[a-z0-9.-]+\.(?:com|net|org|io|in)\b', raw, flags=re.I):
            iocs.append({"type": "domain", "value": dom, "event_idx": e["idx"]})
    return {"events": events, "iocs": iocs}

def fm_mitre_map(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Toy mapping based on keywords. Replace with your classifier as you build it."""
    mitre: List[Dict[str, Any]] = []
    for e in payload.get("events", []):
        raw = (e.get("raw") or "").lower()
        techs = []
        if "failed login" in raw or "bruteforce" in raw:
            techs.append({"technique": "Credential Access", "id": "T1110"})
        if "powershell" in raw or "wmic" in raw:
            techs.append({"technique": "Command and Scripting Interpreter", "id": "T1059"})
        if "rundll32" in raw:
            techs.append({"technique": "Indirect Command Execution", "id": "T1203"})
        if techs:
            mitre.append({"event_idx": e.get("idx"), "techniques": techs})
    return {"events": payload.get("events", []), "iocs": payload.get("iocs", []), "mitre": mitre}

def fm_make_timeline(payload: Dict[str, Any]) -> Dict[str, Any]:
    """Build a clean, human-sized timeline."""
    evs = payload.get("events", [])
    evs_sorted = sorted(evs, key=lambda x: (x.get("timestamp") or "", x.get("idx") or 0))

    timeline: List[Dict[str, Any]] = []
    for e in evs_sorted:
        full = single_line(e.get("raw") or e.get("Message") or "")
        short, was_cut = shorten(full, MAX_SUMMARY_LEN)
        item: Dict[str, Any] = {
            "timestamp": e.get("timestamp"),
            "idx": e.get("idx"),
            "summary": short,
        }
        if was_cut:
            item["full"] = full[:MAX_DETAILS_LEN] + (ELLIPSIS if len(full) > MAX_DETAILS_LEN else "")
            item["truncated"] = True
        timeline.append(item)

    return {
        "timeline": timeline,
        "events": evs_sorted,
        "iocs": payload.get("iocs", []),
        "mitre": payload.get("mitre", []),
        "summary": f"{len(evs_sorted)} events, {len(payload.get('iocs', []))} IOCs, {len(payload.get('mitre', []))} MITRE mappings"
    }

def _html_escape(s: Any) -> str:
    s = "" if s is None else str(s)
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")

def fm_report_html(timeline: List[Dict[str, Any]], iocs: List[Dict[str, Any]], mitre: List[Dict[str, Any]]) -> str:
    """Server-rendered technical report with expanders for long lines."""
    ioc_rows = "\n".join(
        f"<tr><td>{_html_escape(i.get('type'))}</td><td>{_html_escape(i.get('value'))}</td><td>{_html_escape(i.get('event_idx'))}</td></tr>"
        for i in iocs[:500]
    ) or '<tr><td colspan="3">None</td></tr>'

    mitre_rows = "\n".join(
        f"<tr><td>{_html_escape(m.get('event_idx'))}</td><td>{_html_escape(', '.join([x.get('id','') for x in (m.get('techniques') or [])]))}</td></tr>"
        for m in mitre[:500]
    ) or '<tr><td colspan="2">None</td></tr>'

    tl_rows_parts: List[str] = []
    for t in timeline[:1000]:
        ts = _html_escape(t.get("timestamp"))
        idx = _html_escape(t.get("idx"))
        short = _html_escape(t.get("summary"))
        if t.get("truncated") and t.get("full"):
            full = _html_escape(t.get("full"))
            tl_rows_parts.append(
                f"<tr><td class='mono'>{ts}</td>"
                f"<td class='mono'><div>{short}</div>"
                f"<details style='margin-top:6px'><summary>Show full raw</summary>"
                f"<pre style='white-space:pre-wrap'>{full}</pre></details></td>"
                f"<td>{idx}</td></tr>"
            )
        else:
            tl_rows_parts.append(
                f"<tr><td class='mono'>{ts}</td><td class='mono'>{short}</td><td>{idx}</td></tr>"
            )
    tl_rows = "\n".join(tl_rows_parts) or '<tr><td colspan="3">No events</td></tr>'

    html = f"""
    <style>
      .mono {{ font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size:12px; }}
      table {{ border-collapse: collapse; width: 100%; }}
      th, td {{ border: 1px solid #eee; padding: 6px 8px; text-align: left; }}
      th {{ background: #fafafa; }}
    </style>
    <h2>ForensicMind Report</h2>
    <p><strong>Generated:</strong> {datetime.utcnow().isoformat()}Z</p>

    <h3>Indicators of Compromise (IOCs)</h3>
    <table>
      <tr><th>Type</th><th>Value</th><th>Event Idx</th></tr>
      {ioc_rows}
    </table>

    <h3>MITRE ATT&CK Mapping</h3>
    <table>
      <tr><th>Event Idx</th><th>Techniques</th></tr>
      {mitre_rows}
    </table>

    <h3>Timeline</h3>
    <table>
      <tr><th>Timestamp</th><th>Event (short; expand for full)</th><th>Idx</th></tr>
      {tl_rows}
    </table>
    """
    return html

# ================================
# API routes: ForensicMind pipeline
# ================================
_uvlog = logging.getLogger("uvicorn.error")

@app.post("/parse")
def fm_parse_endpoint(inp: FMLogsIn):
    if not inp.logs.strip():
        raise HTTPException(status_code=400, detail="Empty logs.")
    events = fm_parse_lines(inp.logs)
    return {"events": events}

@app.post("/enrich")
def fm_enrich_endpoint(e1: FMEventsIn):
    return fm_enrich(e1.events)

@app.post("/mitre-map")
def fm_mitre_endpoint(payload: Dict[str, Any]):
    if "events" not in payload:
        raise HTTPException(status_code=400, detail="Missing 'events'.")
    return fm_mitre_map(payload)

@app.post("/timeline")
def fm_timeline_endpoint(payload: Dict[str, Any]):
    if "events" not in payload:
        raise HTTPException(status_code=400, detail="Missing 'events'.")
    return fm_make_timeline(payload)

@app.post("/report")
def fm_report_endpoint(payload: Dict[str, Any]):
    """
    Returns:
      {
        "html": "<tables...>",
        "ai": {
          "enabled": bool,
          "easy": "LLM text or reason it was disabled",
          "soc":  "LLM text or reason it was disabled"
        }
      }
    """
    timeline = payload.get("timeline", [])
    iocs = payload.get("iocs", [])
    mitre = payload.get("mitre", [])

    html = fm_report_html(timeline, iocs, mitre)

    ai = {"enabled": False, "easy": "", "soc": ""}
    if _wx_is_configured():
        prompts = _build_prompts_for_report(timeline, iocs, mitre)
        ai["enabled"] = True
        ai["easy"] = _wx_generate(prompts["easy"])
        ai["soc"]  = _wx_generate(prompts["soc"])

    return {"html": html, "ai": ai}

@app.post("/graph-write")
def fm_graph_write_endpoint(payload: Dict[str, Any]):
    # pretend to write to a graph DB; acknowledge
    return {"ok": True, "written_nodes": len(payload.get("events", []))}

# ================================
# API routes: existing graph endpoints
# ================================
@app.get("/health")
def health():
    return {"ok": True}

@app.get("/log-types")
def log_types():
    return list(LOG_TYPES)

@app.get("/graph")
def graph(type: str = Query("application", description="application|system|network")):
    t = type.lower()
    if t not in LOG_TYPES:
        raise HTTPException(status_code=400, detail=f"Invalid type '{type}'. Use one of {LOG_TYPES}.")

    path = LOG_FILE_MAP[t]
    events = _read_jsonl(path)
    using_fallback = not bool(events)

    g = _build_graph_from_events(events) if events else _fallback_sample_graph()
    g["meta"] = {"type": t, "file": str(path), "events": len(events), "fallback": using_fallback}

    _uvlog.info(f"/graph type={t} file={path} events={len(events)} fallback={using_fallback}")
    return g

# ================================
# Optional routers (wrapped)
# ================================
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

# ================================
# Startup banner + data dir check
# ================================
FRONTEND_LINKS = [
    # If you use VS Code Live Server with SentinelMind_starter as root:
    # "http://127.0.0.1:5500/frontend/sentinelvision/index.html",
    # "http://127.0.0.1:5500/frontend/forensicmind/index.html",

    # If your workspace root is the parent folder, include the project folder:
    "http://127.0.0.1:5500/SentinelMind_starter/frontend/sentinelvision/index.html",
    "http://127.0.0.1:5500/SentinelMind_starter/frontend/forensicmind/index.html",
]

@app.on_event("startup")
async def _startup_banner_and_check():
    _uvlog.info(f"DATA_DIR = {DATA_DIR}")
    for k, p in LOG_FILE_MAP.items():
        try:
            size = p.stat().st_size if p.exists() else 0
        except Exception:
            size = "?"
        _uvlog.info(f"  {k}: {p}  exists={p.exists()}  size={size}")

    lines = ["", "🔗 Frontend UIs (Ctrl+Click to open):"]
    for i, url in enumerate(FRONTEND_LINKS, 1):
        lines.append(f"  {i}. {url}")
    lines.append("")
    if not _wx_is_configured():
        lines.append("ℹ Granite summaries: DISABLED (set WATSONX_* env vars and install/updo ibm-watsonx-ai)")
        if WX_IMPORT_ERR:
            lines.append(f"   - SDK import error: {WX_IMPORT_ERR}")
    else:
        lines.append(f"✅ Granite enabled → base={WATSONX_BASE_URL} model={WATSONX_MODEL_ID}")
    _uvlog.info("\n".join(lines))
