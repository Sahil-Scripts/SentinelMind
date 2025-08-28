try:
    from schemas.models import Event
except Exception:
    from backend.schemas.models import Event  # type: ignore

def apply_rules(events: list[Event]) -> list[Event]:
    # Toy rule: >= 5 "fail" messages from same source => brute-force hint
    fails = {}
    for e in events:
        if "fail" in (e.summary or "").lower():
            fails[e.source] = fails.get(e.source, 0) + 1
    for e in events:
        if fails.get(e.source, 0) >= 5 and "brute" not in (e.summary or "").lower():
            e.summary += " [rule:possible brute-force]"
    return events
