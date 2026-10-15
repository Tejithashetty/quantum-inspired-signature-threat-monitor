import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from app.detection import analyze_event, extract_features, verify_message


def signed_message(message):
    private_key = Ed25519PrivateKey.generate()
    public_key = base64.b64encode(private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )).decode("ascii")
    signature = base64.b64encode(private_key.sign(message.encode("utf-8"))).decode("ascii")
    return public_key, signature


def test_ed25519_verifies_original_message():
    message = "test message"
    public_key, signature = signed_message(message)
    assert verify_message(message, public_key, signature) is True


def test_ed25519_rejects_changed_message():
    message = "original"
    public_key, signature = signed_message(message)
    assert verify_message(message + " changed", public_key, signature) is False


def test_malformed_key_or_signature_is_rejected():
    assert verify_message("test", "bad-base64!", "bad-base64!") is False


def test_normal_burst_and_tampered_events_get_expected_risk_order():
    normal = analyze_event(extract_features("normal", True, 1, 1), [])
    burst = analyze_event(extract_features("burst", True, 5, 1), [])
    tampered = analyze_event(extract_features("tampered", False, 1, 1), [])
    assert normal["risk_level"] == "LOW"
    assert burst["risk_level"] == "MEDIUM"
    assert tampered["risk_level"] == "HIGH"


def test_ml_detector_reports_real_event_warmup_without_training_data():
    result = analyze_event(extract_features("first event", True, 1, 1), [])
    assert result["ml_score"] is None
    assert "20 more valid LOW-risk events" in result["ml_status"]


def test_ml_baseline_excludes_suspicious_but_valid_events():
    from app.detection import ml_detector

    feature_row = {
        "message_length": 10,
        "events_last_minute": 1,
        "repeated_events_5m": 1,
        "is_long_message": 0,
        "is_empty_message": 0,
        "signature_invalid": 0,
    }
    history = [
        {**feature_row, "risk_level": "LOW"} for _ in range(19)
    ]
    history.append({**feature_row, "risk_level": "MEDIUM"})

    score, status = ml_detector(feature_row, history)

    assert score is None
    assert "1 more valid LOW-risk events" in status


def test_adaptive_threshold_ignores_suspicious_but_valid_events():
    from app.detection import adaptive_threshold

    history = [
        {"signature_invalid": 0, "risk_level": "LOW", "hybrid_score": 0}
        for _ in range(9)
    ]
    history.append({"signature_invalid": 0, "risk_level": "MEDIUM", "hybrid_score": 100})

    threshold, status = adaptive_threshold(history)

    assert threshold == 40.0
    assert "Default threshold" in status
