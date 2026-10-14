from app.db import (
    count_recent_events_for_key,
    count_recent_repeats,
    detector_history,
    save_event,
)
from app.detection import analyze_event, extract_features, verify_message


def analyze_and_store_event(message: str, public_key: str, signature: str):
    """Shared live-analysis workflow used by both the API and Streamlit UI."""
    if len(message) > 10000:
        raise ValueError("Message must be 10,000 characters or shorter")
    if not public_key or len(public_key) > 200:
        raise ValueError("Public key is required and must be 200 characters or shorter")
    if not signature or len(signature) > 300:
        raise ValueError("Signature is required and must be 300 characters or shorter")

    verified = verify_message(message, public_key, signature)
    recent_key_events = count_recent_events_for_key(public_key) + 1
    repeated_events = count_recent_repeats(public_key, message) + 1
    features = extract_features(message, verified, recent_key_events, repeated_events)
    history = detector_history(public_key)
    result = analyze_event(features, history)
    event_id, received_at = save_event(
        message, public_key, signature, verified, result, features
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
