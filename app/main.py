from html import escape

from fastapi import FastAPI
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field

from app.db import (
    count_recent_events_for_key,
    count_recent_repeats,
    detector_history,
    initialize_db,
    recent_events,
    save_event,
)
from app.detection import analyze_event, extract_features, verify_message

app = FastAPI(title="Signature Threat Monitor", version="0.2.0")


class EventInput(BaseModel):
    message: str = Field(max_length=10000)
    public_key: str = Field(min_length=1, max_length=200)
    signature: str = Field(min_length=1, max_length=300)


@app.on_event("startup")
def startup():
    initialize_db()


@app.get("/", response_class=HTMLResponse)
def dashboard():
    rows = recent_events()
    rendered = []
    for row in rows:
        signature = "Valid" if row["verified"] else "INVALID"
        ml_score = "Warming up" if row["ml_score"] is None else f"{row['ml_score']:.1f}"
        rendered.append(
            "<tr>"
            f"<td>{row['id']}</td><td>{signature}</td><td><strong>{escape(row['risk_level'])}</strong> ({row['risk_score']})</td>"
            f"<td>{row['statistical_score']:.1f}</td><td>{ml_score}</td><td>{row['quantum_score']:.1f}</td>"
            f"<td>{escape(row['message'][:80])}</td><td>{escape(row['reasons'])}</td><td>{escape(row['received_at'])}</td>"
            "</tr>"
        )
    html_rows = "".join(rendered) or '<tr><td colspan="9">No events yet. Submit one using the API instructions.</td></tr>'
    return f"""<!doctype html><html><head><meta charset='utf-8'><meta http-equiv='refresh' content='5'><title>Signature Threat Monitor</title>
    <style>body{{font:15px Arial;margin:28px;background:#f5f7fb;color:#172033}}main{{max-width:1450px;margin:auto}}table{{width:100%;border-collapse:collapse;background:white}}th,td{{padding:9px;border:1px solid #dce2ed;text-align:left;vertical-align:top}}th{{background:#eaf0fa}}.note{{background:#fff4d6;padding:12px}}.alert{{color:#a11}}</style></head>
    <body><main><h1>Digital Signature Threat Monitor</h1><p>Live event dashboard (refreshes every 5 seconds).</p>
    <p class='note'>Live pipeline: Ed25519 verification → feature extraction → statistical + Isolation Forest + QUBO-style scoring → hybrid risk level. ML and adaptive thresholds warm up using real events.</p>
    <p>QUBO-style scoring uses classical arithmetic; this demo does not run on quantum hardware or claim quantum advantage. ML requires 20 prior valid events for the same signing key.</p>
    <h2>Recent events and alerts</h2><table><thead><tr><th>ID</th><th>Signature</th><th>Risk</th><th>Stats</th><th>ML</th><th>QUBO</th><th>Message HMAC fingerprint</th><th>Alert reasons</th><th>Received (UTC)</th></tr></thead><tbody>{html_rows}</tbody></table>
    <p>Submit live signed events at <a href='/docs'>API documentation</a>. Message text is verified in memory; only a keyed fingerprint is stored.</p></main></body></html>"""


@app.post("/api/events")
def create_event(event: EventInput):
    verified = verify_message(event.message, event.public_key, event.signature)
    recent_key_events = count_recent_events_for_key(event.public_key) + 1
    repeated_events = count_recent_repeats(event.public_key, event.message) + 1
    features = extract_features(event.message, verified, recent_key_events, repeated_events)
    history = detector_history(event.public_key)
    result = analyze_event(features, history)
    event_id, received_at = save_event(
        event.message, event.public_key, event.signature, verified, result, features
    )
    return {
        "id": event_id,
        "verified": verified,
        "features": features,
        "detectors": {
            "statistical_score": result["statistical_score"],
            "ml_score": result["ml_score"],
            "ml_status": result["ml_status"],
            "quantum_inspired_score": result["quantum_score"],
            "quantum_inspired_note": result["quantum_status"],
        },
        "hybrid_score": result["hybrid_score"],
        "risk_score": round(result["hybrid_score"]),
        "adaptive_threshold": result["adaptive_threshold"],
        "threshold_status": result["threshold_status"],
        "risk_level": result["risk_level"],
        "alerts": result["alerts"],
        "received_at": received_at,
    }


@app.get("/api/events")
def list_events():
    return [dict(row) for row in recent_events()]
