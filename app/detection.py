import base64
from statistics import median

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


def verify_message(message: str, public_key_b64: str, signature_b64: str) -> bool:
    try:
        public_key = Ed25519PublicKey.from_public_bytes(base64.b64decode(public_key_b64, validate=True))
        signature = base64.b64decode(signature_b64, validate=True)
        public_key.verify(signature, message.encode("utf-8"))
        return True
    except (ValueError, InvalidSignature):
        return False


def extract_features(message: str, verified: bool, recent_key_events: int, repeated_events: int):
    """Extract measurable features from the live event and its recent history."""
    return {
        "message_length": len(message),
        "events_last_minute": recent_key_events,
        "repeated_events_5m": repeated_events,
        "signature_invalid": int(not verified),
        "is_long_message": int(len(message) > 2000),
        "is_empty_message": int(not message.strip()),
    }


def statistical_detector(features, history):
    """Robust median/MAD detector. Returns no score until real baseline events exist."""
    score = 0.0
    details = []
    if features["signature_invalid"]:
        score += 80
        details.append("Signature verification failed")
    if features["events_last_minute"] >= 5:
        score += 55
        details.append("High event rate for this signing key")
    if features["repeated_events_5m"] >= 3:
        score += 40
        details.append("Repeated message pattern for this signing key")
    if features["is_long_message"]:
        score += 10
        details.append("Unusually long message")
    if features["is_empty_message"]:
        score += 20
        details.append("Message is empty or only whitespace")

    # Compare message length with this key's verified live history once there is a baseline.
    lengths = [float(row.get("message_length", 0)) for row in history if row.get("signature_invalid", 1) == 0]
    if len(lengths) >= 5:
        center = median(lengths)
        mad = median([abs(value - center) for value in lengths])
        scale = max(1.0, 1.4826 * mad)
        robust_z = abs(features["message_length"] - center) / scale
        if robust_z >= 3.5:
            score += min(30, 10 * (robust_z - 2.5))
            details.append("Message length differs sharply from this key's recent baseline")
    return min(100.0, score), details


def ml_detector(features, history):
    """Isolation Forest trained only on previously received, validly signed events."""
    normal_rows = [row for row in history if row.get("signature_invalid", 1) == 0]
    if len(normal_rows) < 20:
        return None, f"Warming up: {20 - len(normal_rows)} more valid events needed for the ML baseline"

    from sklearn.ensemble import IsolationForest

    columns = ("message_length", "events_last_minute", "repeated_events_5m", "is_long_message", "is_empty_message")
    matrix = [[float(row.get(column, 0)) for column in columns] for row in normal_rows]
    model = IsolationForest(n_estimators=100, contamination="auto", random_state=42)
    model.fit(matrix)
    reference_scores = model.score_samples(matrix)
    candidate = [float(features.get(column, 0)) for column in columns]
    candidate_score = model.score_samples([candidate])[0]
    # A low Isolation Forest score is more anomalous; express its rank on a 0–100 scale.
    anomaly_score = 100.0 * sum(value > candidate_score for value in reference_scores) / len(reference_scores)
    return round(anomaly_score, 1), f"Isolation Forest used {len(normal_rows)} real verified events"


def quantum_inspired_detector(features):
    """Evaluate a small QUBO-style risk energy with binary event indicators.

    This is ordinary classical arithmetic inspired by QUBO/Ising formulations;
    it does not run on quantum hardware or establish quantum advantage.
    """
    invalid = features["signature_invalid"]
    burst = int(features["events_last_minute"] >= 5)
    repeated = int(features["repeated_events_5m"] >= 3)
    long_message = features["is_long_message"]
    empty_message = features["is_empty_message"]
    # Linear terms plus pairwise couplings let combinations contribute extra risk.
    risk_energy = (
        50 * invalid + 50 * burst + 40 * repeated + 10 * long_message + 15 * empty_message
        + 15 * invalid * burst + 12 * burst * repeated + 10 * invalid * repeated
    )
    return float(min(100, risk_energy)), "Classical QUBO-style feature interaction score"


def adaptive_threshold(history):
    """Use previous real hybrid scores when enough are available; otherwise use a stated default."""
    prior = [float(row["hybrid_score"]) for row in history
             if row.get("hybrid_score") is not None and row.get("signature_invalid", 1) == 0]
    if len(prior) < 10:
        return 40.0, "Default threshold (adaptive threshold warms up after 10 prior valid events)"
    center = median(prior)
    mad = median([abs(value - center) for value in prior])
    threshold = center + max(10.0, 3.0 * 1.4826 * mad)
    return round(min(85.0, max(30.0, threshold)), 1), "Adaptive threshold from recent real valid-event scores"


def analyze_event(features, history):
    statistical_score, statistical_reasons = statistical_detector(features, history)
    ml_score, ml_status = ml_detector(features, history)
    quantum_score, quantum_status = quantum_inspired_detector(features)

    # Renormalize weights while the ML baseline is warming up.
    weighted = [(statistical_score, 0.40), (quantum_score, 0.30)]
    if ml_score is not None:
        weighted.append((ml_score, 0.30))
    hybrid_score = sum(score * weight for score, weight in weighted) / sum(weight for _, weight in weighted)
    threshold, threshold_status = adaptive_threshold(history)

    if hybrid_score >= max(80, threshold + 25):
        risk_level = "CRITICAL"
    elif hybrid_score >= max(60, threshold + 10):
        risk_level = "HIGH"
    elif hybrid_score >= threshold:
        risk_level = "MEDIUM"
    else:
        risk_level = "LOW"

    alerts = list(dict.fromkeys(statistical_reasons))
    if risk_level != "LOW":
        # Explain threshold-based classifications too, including MEDIUM events
        # where none of the individual statistical rules fired.
        score_explanation = (
            f"Hybrid score {hybrid_score:.1f} met or exceeded the "
            f"{threshold_status.lower()} ({threshold:.1f})"
        )
        if ml_score is not None:
            score_explanation += f"; ML anomaly score was {ml_score:.1f}/100"
        alerts.append(score_explanation)
    if not alerts:
        alerts.append("No detector raised a specific alert")

    return {
        "statistical_score": round(statistical_score, 1),
        "ml_score": ml_score,
        "ml_status": ml_status,
        "quantum_score": round(quantum_score, 1),
        "quantum_status": quantum_status,
        "hybrid_score": round(hybrid_score, 1),
        "adaptive_threshold": threshold,
        "threshold_status": threshold_status,
        "risk_level": risk_level,
        "alerts": alerts,
    }
