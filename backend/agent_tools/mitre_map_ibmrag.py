try:
    from schemas.models import Event
except Exception:
    from backend.schemas.models import Event  # type: ignore

LOOKUPS = [
    ("ssh",     ("Credential Access", "T1110 Brute Force")),
    ("brute",   ("Credential Access", "T1110 Brute Force")),
    ("rdp",     ("Lateral Movement",  "T1021 Remote Services")),
    ("lateral", ("Lateral Movement",  "T1021 Remote Services")),
    ("exfil",   ("Exfiltration",      "T1041 Exfiltration Over C2")),
    ("scp",     ("Exfiltration",      "T1048 Exfiltration Over Alt Protocol")),
]

def map_events_to_mitre(events: list[Event]) -> list[Event]:
    for e in events:
        text = (e.summary or "").lower()
        assigned = False
        for key, (tac, tech) in LOOKUPS:
            if key in text:
                e.tactic, e.technique = tac, tech
                assigned = True
                break
        if not assigned and not e.tactic:
            e.tactic, e.technique = "Discovery", ""
    return events
