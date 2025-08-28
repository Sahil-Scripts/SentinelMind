try:
    from schemas.models import Event
except Exception:
    from backend.schemas.models import Event  # type: ignore

BAD_IPS = {"203.0.113.66", "198.51.100.42", "192.0.2.9"}

def enrich_events(events: list[Event]) -> list[Event]:
    for e in events:
        found = []
        for tok in str(e.raw.get("line", "")).replace(",", " ").split():
            if tok in BAD_IPS:
                found.append(tok)
        if found:
            e.iocs = sorted(set((e.iocs or []) + found))
    return events
