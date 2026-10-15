import pytest

from app.db import _fingerprint_key, message_fingerprint


def test_fingerprint_is_keyed_and_does_not_contain_message():
    message = "private sample message"
    fingerprint = message_fingerprint(message)
    assert fingerprint.startswith("hmac-sha256:")
    assert message not in fingerprint
    assert len(fingerprint) == len("hmac-sha256:") + 64


def test_same_message_has_same_local_fingerprint():
    assert message_fingerprint("repeat test") == message_fingerprint("repeat test")


def test_different_messages_have_different_fingerprints():
    assert message_fingerprint("first") != message_fingerprint("second")


def test_hosted_database_requires_stable_fingerprint_secret(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://example.invalid/db")
    monkeypatch.delenv("FINGERPRINT_KEY", raising=False)
    with pytest.raises(RuntimeError, match="FINGERPRINT_KEY is required"):
        _fingerprint_key()


def test_hosted_fingerprint_uses_configured_secret(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql://example.invalid/db")
    monkeypatch.setenv("FINGERPRINT_KEY", "student-demo-stable-secret")
    first = message_fingerprint("same event")
    second = message_fingerprint("same event")
    assert first == second
    assert "same event" not in first
