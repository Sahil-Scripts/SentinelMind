import re, uuid
try:
    from schemas.models import Event
except Exception:
    from backend.schemas.models import Event  # type: ignore

PAT_ARROW  = re.compile(r"^([0-9TZ:\-]+)\s+(\S+)\s*->\s*(\S+)\s*:\s*(.+)$")
PAT_SIMPLE = re.compile(r"^([0-9TZ:\-]+)\s+(\S+)\s*:\s*(.+)$")

def parse_logs(text: str):
    events = []
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        m = PAT_ARROW.match(s)
        if m:
            t, src, dst, msg = m.groups()
        else:
            m2 = PAT_SIMPLE.match(s)
            if not m2:
                continue
            t, src, msg = m2.groups()
            dst = src
        events.append(Event(
            id=str(uuid.uuid4()),
            time=t, source=src, target=dst, summary=msg,
            raw={"line": line}
        ))
    return events
