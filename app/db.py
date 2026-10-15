from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from pathlib import Path

DB_PATH = Path(__file__).resolve().parent.parent / "events.db"
FINGERPRINT_KEY_PATH = Path(__file__).resolve().parent.parent / "keys" / "fingerprint.key"


def _setting(name):
    """Read a setting from environment variables or Streamlit's private secrets."""
    value = os.environ.get(name)
    if value:
        return value
    try:
        import streamlit as st

        return st.secrets.get(name)
    except Exception:
        # FastAPI and local command-line use do not necessarily have Streamlit secrets.
        return None


def _database_url():
    return _setting("DATABASE_URL")


def _using_postgres():
    return bool(_database_url())


def _fingerprint_key():
    configured_key = _setting("FINGERPRINT_KEY")
    if configured_key:
        return configured_key.encode("utf-8")
    if _using_postgres():
        raise RuntimeError(
            "FINGERPRINT_KEY is required when DATABASE_URL is configured. "
            "Set both values in Streamlit secrets."
        )

    # SQLite development mode keeps its key beside the local database. Both files
    # are gitignored. PostgreSQL mode uses the stable FINGERPRINT_KEY secret above.
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


@contextmanager
def connect():
    """Open the configured PostgreSQL database or the local SQLite database."""
    database_url = _database_url()
    if database_url:
        import psycopg
        from psycopg.rows import dict_row

        connection = psycopg.connect(
            database_url,
            row_factory=dict_row,
            # Compatible with transaction poolers as well as direct connections.
            prepare_threshold=None,
        )
    else:
        connection = sqlite3.connect(DB_PATH)
        connection.row_factory = sqlite3.Row

    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()


def _execute(connection, statement, parameters=()):
    if _using_postgres():
        statement = statement.replace("?", "%s")
    return connection.execute(statement, parameters)


def initialize_db():
    if _using_postgres():
        with connect() as connection:
            _execute(connection, """
                CREATE TABLE IF NOT EXISTS events (
                    id BIGSERIAL PRIMARY KEY,
                    message TEXT NOT NULL,
                    public_key TEXT NOT NULL,
                    signature TEXT NOT NULL,
                    verified INTEGER NOT NULL,
                    risk_score INTEGER NOT NULL,
                    reasons TEXT NOT NULL,
                    received_at TEXT NOT NULL
                )
            """)
            migrations = {
                "features_json": "TEXT NOT NULL DEFAULT '{}'",
                "statistical_score": "DOUBLE PRECISION NOT NULL DEFAULT 0",
                "ml_score": "DOUBLE PRECISION",
                "quantum_score": "DOUBLE PRECISION NOT NULL DEFAULT 0",
                "hybrid_score": "DOUBLE PRECISION NOT NULL DEFAULT 0",
                "adaptive_threshold": "DOUBLE PRECISION NOT NULL DEFAULT 55",
                "risk_level": "TEXT NOT NULL DEFAULT 'LOW'",
            }
            for name, definition in migrations.items():
                _execute(
                    connection,
                    f"ALTER TABLE events ADD COLUMN IF NOT EXISTS {name} {definition}",
                )
            _migrate_legacy_messages(connection)
            _execute(connection, """
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
        return

    with connect() as connection:
        _execute(connection, """
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
        _migrate_legacy_messages(connection)
        existing = {row["name"] for row in _execute(connection, "PRAGMA table_info(events)")}
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
                _execute(connection, f"ALTER TABLE events ADD COLUMN {name} {definition}")
        _execute(connection, """
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


def _migrate_legacy_messages(connection):
    # Replace any plaintext messages from the earlier demo version with keyed fingerprints.
    # Filter in Python instead of using SQL LIKE with a '%' wildcard. Psycopg
    # treats percent signs as parameter markers when a parameter tuple is passed.
    all_messages = _execute(connection, "SELECT id, message FROM events").fetchall()
    legacy_messages = [
        row for row in all_messages
        if not row["message"].startswith("hmac-sha256:")
    ]
    for row in legacy_messages:
        _execute(
            connection,
            "UPDATE events SET message = ? WHERE id = ?",
            (message_fingerprint(row["message"]), row["id"]),
        )


def save_event(message, public_key, signature, verified, result, features):
    received_at = datetime.now(timezone.utc).isoformat()
    values = (
        message_fingerprint(message), public_key, signature, int(verified),
        round(result["hybrid_score"]), "; ".join(result["alerts"]), received_at,
        json.dumps(features), result["statistical_score"], result["ml_score"],
        result["quantum_score"], result["hybrid_score"],
        result["adaptive_threshold"], result["risk_level"],
    )
    with connect() as connection:
        if _using_postgres():
            cursor = _execute(connection, """
                INSERT INTO events (
                    message, public_key, signature, verified, risk_score, reasons, received_at,
                    features_json, statistical_score, ml_score, quantum_score, hybrid_score,
                    adaptive_threshold, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) RETURNING id
            """, values)
            event_id = cursor.fetchone()["id"]
        else:
            cursor = _execute(connection, """
                INSERT INTO events (
                    message, public_key, signature, verified, risk_score, reasons, received_at,
                    features_json, statistical_score, ml_score, quantum_score, hybrid_score,
                    adaptive_threshold, risk_level
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, values)
            event_id = cursor.lastrowid
    return event_id, received_at


def recent_events(limit=100):
    with connect() as connection:
        return _execute(
            connection, "SELECT * FROM events ORDER BY id DESC LIMIT ?", (limit,)
        ).fetchall()


def count_recent_events_for_key(public_key, seconds=60):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    with connect() as connection:
        row = _execute(connection, """
            SELECT COUNT(*) AS total FROM events WHERE public_key = ? AND received_at >= ?
        """, (public_key, cutoff)).fetchone()
        return row["total"]


def count_recent_repeats(public_key, message, seconds=300):
    cutoff = (datetime.now(timezone.utc) - timedelta(seconds=seconds)).isoformat()
    fingerprint = message_fingerprint(message)
    with connect() as connection:
        row = _execute(connection, """
            SELECT COUNT(*) AS total FROM events
            WHERE public_key = ? AND message = ? AND received_at >= ?
        """, (public_key, fingerprint, cutoff)).fetchone()
        return row["total"]


def detector_history(public_key, limit=500):
    with connect() as connection:
        rows = _execute(connection, """
            SELECT features_json, hybrid_score FROM events
            WHERE public_key = ? ORDER BY id DESC LIMIT ?
        """, (public_key, limit)).fetchall()
    result = []
    for row in rows:
        try:
            features = json.loads(row["features_json"] or "{}")
        except json.JSONDecodeError:
            features = {}
        features["hybrid_score"] = row["hybrid_score"]
        result.append(features)
    return result
