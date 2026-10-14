from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "events.db"
FINGERPRINT_KEY_PATH = Path(__file__).resolve().parent.parent / "keys" / "fingerprint.key"


def _fingerprint_key():
    FINGERPRINT_KEY_PATH.parent.mkdir(exist_ok=True)
    try:
        return FINGERPRINT_KEY_PATH.read_bytes()
    except FileNotFoundError:
        key = secrets.token_bytes(32)
        try:
            with FINGERPRINT_KEY_PATH.open("xb") as key_file:
                key_file.write(key)
        except FileExistsError:
            pass
        return FINGERPRINT_KEY_PATH.read_bytes()


def message_fingerprint(message):
    digest = hmac.new(_fingerprint_key(), message.encode("utf-8"), hashlib.sha256).hexdigest()
    return "hmac-sha256:" + digest


def connect():
    connection = sqlite3.connect(DB_PATH)
    connection.row_factory = sqlite3.Row
    return connection


def initialize_db():
    with connect() as connection:
        connection.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                message TEXT NOT NULL,
                public_key TEXT NOT NULL,
                signature TEXT NOT NULL,
                verified INTEGER NOT NULL,
                risk_score INTEGER NOT NULL,
                reasons TEXT NOT NULL,
                received_at TEXT NOT NULL
            )
        """)
        # Replace any plaintext messages from the earlier demo version with keyed fingerprints.
        legacy_messages = connection.execute(
            "SELECT id, message FROM events WHERE message NOT LIKE 'hmac-sha256:%'"
        ).fetchall()
        for row in legacy_messages:
            connection.execute(
                "UPDATE events SET message = ? WHERE id = ?",
                (message_fingerprint(row["message"]), row["id"]),
            )
        # Add detector fields to databases created by the earlier starter milestone.
        existing = {row["name"] for row in connection.execute("PRAGMA table_info(events)")}
        migrations = {
            "features_json": "TEXT NOT NULL DEFAULT '{}'",
            "statistical_score": "REAL NOT NULL DEFAULT 0",
            "ml_score": "REAL",
            "quantum_score": "REAL NOT NULL DEFAULT 0",
            "hybrid_score": "REAL NOT NULL DEFAULT 0",
            "adaptive_threshold": "REAL NOT NULL DEFAULT 55",
            "risk_level": "TEXT NOT NULL DEFAULT 'LOW'",
        }
        for name, definition in migrations.items():
            if name not in existing:
                connection.execute(f"ALTER TABLE events ADD COLUMN {name} {definition}")
        # Preserve the meaning of starter-version events in the expanded dashboard.
        connection.execute("""
            UPDATE events SET
                statistical_score = risk_score,
                hybrid_score = risk_score,
                adaptive_threshold = 40,
                risk_level = CASE
                    WHEN risk_score >= 85 THEN 'CRITICAL'
                    WHEN risk_score >= 60 THEN 'HIGH'
                    WHEN risk_score >= 40 THEN 'MEDIUM'
                    ELSE 'LOW'
                END
            WHERE features_json = '{}'
        """)


def save_event(message, public_key, signature, verified, result, features):
    received_at = datetime.now(timezone.utc).isoformat()
    with connect() as connection:
        cursor = connection.execute(
            """INSERT INTO events (
                message, public_key, signature, verified, risk_score, reasons, received_at,
                features_json, statistical_score, ml_score, quantum_score, hybrid_score,
                adaptive_threshold, risk_level
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
            (message_fingerprint(message), public_key, signature, int(verified), round(result["hybrid_score"]),
             "; ".join(result["alerts"]), received_at, json.dumps(features),
             result["statistical_score"], result["ml_score"], result["quantum_score"],
             result["hybrid_score"], result["adaptive_threshold"], result["risk_level"]),
        )
        return cursor.lastrowid, received_at


def recent_events(limit=100):
    with connect() as connection:
        return connection.execute("SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)).fetchall()


def count_recent_events_for_key(public_key, seconds=60):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM events WHERE public_key = ? AND received_at >= ?",
            (public_key, cutoff),
        ).fetchone()
        return row["total"]


def count_recent_repeats(public_key, message, seconds=300):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    fingerprint = message_fingerprint(message)
    with connect() as connection:
        row = connection.execute(
            "SELECT COUNT(*) AS total FROM events WHERE public_key = ? AND message = ? AND received_at >= ?",
            (public_key, fingerprint, cutoff),
        ).fetchone()
        return row["total"]


def detector_history(public_key, limit=500):
    with connect() as connection:
        rows = connection.execute(
            "SELECT features_json, hybrid_score FROM events WHERE public_key = ? ORDER BY id DESC LIMIT ?",
            (public_key, limit),
        ).fetchall()
    result = []
    for row in rows:
        try:
            features = json.loads(row["features_json"] or "{}")
        except json.JSONDecodeError:
            features = {}
        features["hybrid_score"] = row["hybrid_score"]
        result.append(features)
    return result
