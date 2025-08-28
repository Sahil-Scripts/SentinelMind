import os
from typing import List

try:
    from ibm_watsonx_ai import Credentials, WatsonxAI
except Exception:
    Credentials = WatsonxAI = None

GRANITE_API_KEY = os.getenv("IBM_WATSONX_APIKEY")
GRANITE_PROJECT_ID = os.getenv("IBM_PROJECT_ID")
GRANITE_URL = os.getenv("IBM_WATSONX_URL", "https://us-south.ml.cloud.ibm.com")
GRANITE_MODEL_ID = os.getenv("IBM_WATSONX_MODEL_ID", "ibm/granite-13b-instruct-v2")

client = None
if GRANITE_API_KEY and GRANITE_PROJECT_ID and Credentials and WatsonxAI:
    creds = Credentials(url=GRANITE_URL, api_key=GRANITE_API_KEY)
    client = WatsonxAI(credentials=creds, project_id=GRANITE_PROJECT_ID)

def _local_html(timeline, iocs: List[str]) -> str:
    """Fallback if Granite is unavailable."""
    from html import escape
    rows = "\n".join([
        f"<tr><td>{e.stepNum}</td><td>{escape(e.time)}</td><td>{escape(e.source)}</td>"
        f"<td>{escape(e.target)}</td><td>{escape(e.tactic or '-')}</td>"
        f"<td>{escape(e.technique or '-')}</td><td>{escape(e.summary)}</td></tr>"
        for e in timeline.events
    ])
    return f"<h1>ForensicMind Report (Local Fallback)</h1><table>{rows}</table>"

def generate_report_html(timeline, iocs: List[str]) -> str:
    if not client:
        return _local_html(timeline, iocs)

    events_txt = "\n".join([
        f"{e.stepNum}. {e.time} | {e.source}->{e.target} | {e.tactic}/{e.technique} | {e.summary}"
        for e in timeline.events
    ])
    ioc_txt = ", ".join(iocs) if iocs else "None"
    prompt = f"""
    You are a cyber forensics analyst. Given this timeline:

    {events_txt}

    IOCs: {ioc_txt}

    Generate a structured HTML report with:
    - Executive Summary
    - Timeline of Events (table)
    - IOCs
    - MITRE ATT&CK mapping
    - Remediation Steps
    """
    try:
        resp = client.generate_text(
            model_id=GRANITE_MODEL_ID,
            input=prompt,
            parameters={"max_new_tokens": 800, "temperature": 0.3}
        )
        return resp["results"][0]["generated_text"]
    except Exception:
        return _local_html(timeline, iocs)
