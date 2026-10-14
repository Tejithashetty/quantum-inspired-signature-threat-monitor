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
    assert "20 more valid events" in result["ml_status"]
