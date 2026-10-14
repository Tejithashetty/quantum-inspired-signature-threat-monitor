from app.db import message_fingerprint


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
