try:
    from schemas.models import Event, Timeline
except Exception:
    from backend.schemas.models import Event, Timeline  # type: ignore

def build_timeline(events: list[Event]) -> Timeline:
    evs = sorted(events, key=lambda e: e.time)
    for i, e in enumerate(evs, start=1):
        e.stepNum = i
    return Timeline(events=evs)
