import time
from typing import Dict, Any, List, Optional
from app.utils import generate_span_id


def create_string_attr(key: str, value: str) -> Dict[str, Any]:
    return {"key": key, "value": {"stringValue": str(value)}}


def create_int_attr(key: str, value: int) -> Dict[str, Any]:
    return {"key": key, "value": {"intValue": value}}


class OTLPBuilder:
    """
    Constructs and maintains compliant OpenTelemetry JSON traces for incident runs.
    """

    def __init__(self, run_id: str, public_marker: str, trace_id: str, server_span_id: str, parent_span_id: Optional[str] = None):
        self.run_id = run_id
        self.public_marker = public_marker
        self.trace_id = trace_id
        self.server_span_id = server_span_id
        self.parent_span_id = parent_span_id
        self.agent_span_id = generate_span_id()
        self.spans: List[Dict[str, Any]] = []

        self.base_attrs = [
            create_string_attr("ga5.run.id", self.run_id),
            create_string_attr("ga5.public.marker", self.public_marker)
        ]

        # 1. SERVER POST /v2/incidents
        server_span = {
            "traceId": self.trace_id,
            "spanId": self.server_span_id,
            "name": "POST /v2/incidents",
            "kind": 2,  # SERVER
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": list(self.base_attrs),
            "status": {}
        }
        if self.parent_span_id:
            server_span["parentSpanId"] = self.parent_span_id
        self.spans.append(server_span)

        # 2. INTERNAL invoke_agent incident-response
        self.spans.append({
            "traceId": self.trace_id,
            "spanId": self.agent_span_id,
            "parentSpanId": self.server_span_id,
            "name": "invoke_agent incident-response",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": list(self.base_attrs),
            "status": {}
        })

    def add_model_span(self, model_name: str, span_id: str):
        """Adds CLIENT chat incident-plan span (exactly one)."""
        attrs = list(self.base_attrs) + [
            create_string_attr("gen_ai.operation.name", "chat"),
            create_string_attr("gen_ai.request.model", model_name or "gpt-4o-mini")
        ]
        self.spans.append({
            "traceId": self.trace_id,
            "spanId": span_id,
            "parentSpanId": self.agent_span_id,
            "name": "chat incident-plan",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": attrs,
            "status": {}
        })

    def add_logical_tool_span(self, tool_name: str, action_id: str, call_id: str, span_id: str) -> Dict[str, Any]:
        """Adds INTERNAL execute_tool <toolName> logical span."""
        attrs = list(self.base_attrs) + [
            create_string_attr("ga5.action.id", action_id),
            create_string_attr("gen_ai.tool.name", tool_name),
            create_string_attr("gen_ai.tool.call.id", call_id),
            create_string_attr("gen_ai.operation.name", "execute_tool")
        ]
        span = {
            "traceId": self.trace_id,
            "spanId": span_id,
            "parentSpanId": self.agent_span_id,
            "name": f"execute_tool {tool_name}",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": attrs,
            "status": {}
        }
        self.spans.append(span)
        return span

    def add_physical_tool_client_span(
        self,
        tool_name: str,
        action_id: str,
        logical_span_id: str,
        client_span_id: str,
        attempt: int = 1,
        receipt_id: Optional[str] = None,
        receipt_nonce: Optional[str] = None,
        status_code: int = 200,
        result_class: Optional[str] = None,
        error_type: Optional[str] = None
    ):
        """Adds CLIENT POST tool/<toolName> physical span."""
        attrs = list(self.base_attrs) + [
            create_string_attr("ga5.action.id", action_id),
            create_int_attr("ga5.attempt", attempt),
            create_string_attr("http.request.method", "POST"),
            create_int_attr("http.request.resend_count", max(0, attempt - 1))
        ]

        if receipt_id:
            attrs.append(create_string_attr("ga5.receipt.id", receipt_id))
        if receipt_nonce:
            attrs.append(create_string_attr("ga5.receipt.nonce", receipt_nonce))

        span_status = {}
        if status_code == 503:
            span_status = {"code": 2}
            attrs.append(create_string_attr("error.type", "503"))
        elif error_type == "timeout" or status_code == 0:
            span_status = {"code": 2}
            attrs.append(create_string_attr("error.type", "timeout"))
        elif status_code == 200:
            span_status = {"code": 1}

        self.spans.append({
            "traceId": self.trace_id,
            "spanId": client_span_id,
            "parentSpanId": logical_span_id,
            "name": f"POST tool/{tool_name}",
            "kind": 3,  # CLIENT
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": attrs,
            "status": span_status
        })

    def add_incident_join_span(self, logical_span_ids: List[str]):
        """Adds INTERNAL incident.join span linking diagnostic execute_tool spans."""
        links = [{"traceId": self.trace_id, "spanId": sid} for sid in logical_span_ids]
        self.spans.append({
            "traceId": self.trace_id,
            "spanId": generate_span_id(),
            "parentSpanId": self.agent_span_id,
            "name": "incident.join",
            "kind": 1,  # INTERNAL
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": list(self.base_attrs),
            "status": {},
            "links": links
        })

    def add_approval_gate_span(self, approval_id: str, receipt_nonce: Optional[str] = None):
        """Adds or updates INTERNAL approval_gate span."""
        existing = next((s for s in self.spans if s["name"] == "approval_gate"), None)
        if existing:
            if receipt_nonce:
                existing["attributes"].append(create_string_attr("ga5.approval.receipt_nonce", receipt_nonce))
        else:
            attrs = list(self.base_attrs) + [
                create_string_attr("ga5.approval.id", approval_id)
            ]
            if receipt_nonce:
                attrs.append(create_string_attr("ga5.approval.receipt_nonce", receipt_nonce))

            self.spans.append({
                "traceId": self.trace_id,
                "spanId": generate_span_id(),
                "parentSpanId": self.agent_span_id,
                "name": "approval_gate",
                "kind": 1,  # INTERNAL
                "startTimeUnixNano": "1700000000000000000",
                "endTimeUnixNano": "1700000000010000000",
                "attributes": attrs,
                "status": {}
            })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "resourceSpans": [
                {
                    "scopeSpans": [
                        {
                            "spans": self.spans
                        }
                    ]
                }
            ]
        }
