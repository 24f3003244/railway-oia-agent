import json
import sqlite3
from typing import Optional, Tuple, Dict, Any
from app.telemetry import OTLPBuilder

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


def serialize_state(state_dict: Dict[str, Any]) -> str:
    d = dict(state_dict)
    otlp = d.get("otlpBuilder")
    if isinstance(otlp, OTLPBuilder):
        d["otlp_data"] = otlp.to_dict()
        d["agentSpanId"] = otlp.agent_span_id
        del d["otlpBuilder"]
    return json.dumps(d)


def deserialize_state(state_json: str) -> Dict[str, Any]:
    d = json.loads(state_json)
    if "otlp_data" in d and "otlpBuilder" not in d:
        otlp_data = d["otlp_data"]
        spans = otlp_data.get("resourceSpans", [{}])[0].get("scopeSpans", [{}])[0].get("spans", [])
        otlp = OTLPBuilder(
            run_id=d["runId"],
            public_marker=d["publicMarker"],
            trace_id=d["traceId"],
            server_span_id=d["serverSpanId"],
            parent_span_id=d.get("parentSpanId"),
            agent_span_id=d.get("agentSpanId"),
            existing_spans=spans
        )
        d["otlpBuilder"] = otlp
    return d


def get_run(run_id: str) -> Optional[Tuple[str, Dict[str, Any]]]:
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT payload_hash, state_json FROM runs WHERE run_id = ?", (run_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], deserialize_state(row[1])
    return None


def save_run(run_id: str, payload_hash: str, state_dict: Dict[str, Any]):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    state_json = serialize_state(state_dict)
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
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT run_id, payload_hash FROM receipts WHERE receipt_id = ?", (receipt_id,))
    row = cursor.fetchone()
    conn.close()
    if row:
        return row[0], row[1]
    return None


def save_receipt(receipt_id: str, run_id: str, payload_hash: str):
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
