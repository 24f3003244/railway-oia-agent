import json
import sqlite3
from typing import Optional, Tuple, Dict, Any

DB_PATH = "incidents.db"


def init_db():
    """Initializes the SQLite database tables."""
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS runs (
            run_id TEXT PRIMARY KEY,
            payload_hash TEXT NOT NULL,
            state_json TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS receipts (
            receipt_id TEXT PRIMARY KEY,
            run_id TEXT NOT NULL,
            payload_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    """)
    conn.commit()
    conn.close()


def get_run(run_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    """
    Returns (payload_hash, state_dict) for given run_id or None if not found.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT payload_hash, state_json FROM runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], json.loads(row[1])
    return None


def save_run(run_id: str, payload_hash: str, state_dict: Dict[str, Any]):
    """
    Saves or updates run state.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    state_json = json.dumps(state_dict)
    cursor.execute("""
        INSERT INTO runs (run_id, payload_hash, state_json, updated_at)
        VALUES (?, ?, ?, CURRENT_TIMESTAMP)
        ON CONFLICT(run_id) DO UPDATE SET
            state_json = excluded.state_json,
            updated_at = CURRENT_TIMESTAMP
    """, (run_id, payload_hash, state_json))
    conn.commit()
    conn.close()


def get_receipt(receipt_id: str) -> Optional[Tuple[str, str]]:
    """
    Returns (run_id, payload_hash) for given receipt_id or None if not found.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT run_id, payload_hash FROM receipts WHERE receipt_id = ?", (receipt_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return None


def save_receipt(receipt_id: str, run_id: str, payload_hash: str):
    """
    Saves processed receipt_id record.
    """
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO receipts (receipt_id, run_id, payload_hash)
        VALUES (?, ?, ?)
        ON CONFLICT(receipt_id) DO UPDATE SET
            payload_hash = excluded.payload_hash
    """, (receipt_id, run_id, payload_hash))
    conn.commit()
    conn.close()
