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
    return f"{prefix}_{secrets.token_hex(8)}"


def parse_traceparent(traceparent: Optional[str]) -> Tuple[str, Optional[str]]:
    """
    Parses a W3C traceparent header of format '00-<trace_id>-<span_id>-01'.
    Returns (trace_id, parent_span_id).
    If invalid or absent, returns fresh (new_trace_id, None).
    """
    if traceparent:
        parts = traceparent.split('-')
        if len(parts) == 4 and parts[0] == '00':
            trace_id, parent_span_id = parts[1], parts[2]
            if len(trace_id) == 32 and len(parent_span_id) == 16:
                try:
                    int(trace_id, 16)
                    int(parent_span_id, 16)
                    return trace_id.lower(), parent_span_id.lower()
                except ValueError:
                    pass
    return generate_trace_id(), None


def format_traceparent(trace_id: str, span_id: str) -> str:
    """Formats traceparent string according to W3C Trace Context spec."""
    return f"00-{trace_id.lower()}-{span_id.lower()}-01"


def extract_evidence_ids(transcript: str) -> List[str]:
    """
    Extracts evidence IDs from line prefixes starting with '[ID]'.
    Falls back to inline bracketed IDs if line-prefix IDs are absent.
    """
    result = []
    seen = set()

    for line in transcript.splitlines():
        line = line.strip()
        m = re.match(r'^\[([a-zA-Z0-9_\-]+)\]', line)
        if m:
            ev_id = m.group(1)
            if ev_id not in seen:
                seen.add(ev_id)
                result.append(ev_id)

    if not result:
        pattern = r'\[([a-zA-Z0-9_\-]+)\]'
        matches = re.findall(pattern, transcript)
        for m in matches:
            if m not in seen:
                seen.add(m)
                result.append(m)

    return result


def compute_bytes_hash(raw_bytes: bytes) -> str:
    """Computes SHA-256 hash of raw bytes."""
    return hashlib.sha256(raw_bytes).hexdigest()
