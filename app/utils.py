import hashlib
import json
import re
import secrets
from typing import List, Optional, Tuple


def generate_trace_id() -> str:
    """Generates a 32-character lowercase hex string for trace ID."""
    return secrets.token_hex(16)


def generate_span_id() -> str:
    """Generates a 16-character lowercase hex string for span ID."""
    return secrets.token_hex(8)


def generate_opaque_id(prefix: str = "id") -> str:
    """Generates a stable opaque ID of at least 8 characters."""
    return f"{prefix}_{secrets.token_hex(6)}"


def parse_traceparent(traceparent: Optional[str]) -> Tuple[str, str]:
    """
    Parses a W3C traceparent header of format '00-<trace_id>-<span_id>-01'.
    Returns (trace_id, parent_span_id).
    If invalid or absent, returns fresh (new_trace_id, new_span_id).
    """
    if traceparent:
        parts = traceparent.split('-')
        if len(parts) == 4 and parts[0] == '00':
            trace_id, parent_span_id = parts[1], parts[2]
            if len(trace_id) == 32 and len(parent_span_id) == 16:
                try:
                    int(trace_id, 16)
                    int(parent_span_id, 16)
                    return trace_id, parent_span_id
                except ValueError:
                    pass
    return generate_trace_id(), generate_span_id()


def format_traceparent(trace_id: str, span_id: str) -> str:
    """Formats traceparent string according to W3C Trace Context spec."""
    return f"00-{trace_id}-{span_id}-01"


def extract_evidence_ids(transcript: str) -> List[str]:
    """
    Extracts all evidence IDs from transcript lines starting with '[ev_...]'.
    """
    pattern = r'\[(ev_[a-zA-Z0-9_\-]+)\]'
    matches = re.findall(pattern, transcript)
    # Deduplicate preserving order
    seen = set()
    result = []
    for m in matches:
        if m not in seen:
            seen.add(m)
            result.append(m)
    return result


def compute_payload_hash(data: dict) -> str:
    """
    Computes deterministic SHA-256 hash of a dictionary/json payload.
    """
    compact_json = json.dumps(data, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest()
