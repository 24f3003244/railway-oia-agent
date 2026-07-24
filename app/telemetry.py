import time
from typing import Dict, Any, List, Optional
from app.utils import generate_span_id


def create_string_attr(key: str, value: str) -> Dict[str, Any]:
    return {"key": key, "value": {"stringValue": str(value)}}


def create_int_attr(key: str, value: int) -> Dict[str, Any]:
    return {"key": key, "value": {"intValue": str(value)}}


def create_span(
    name: str,
    kind: int,
    trace_id: str,
    span_id: str,
    parent_span_id: Optional[str] = None,
    attributes: Optional[List[Dict[str, Any]]] = None,
    start_time_nano: Optional[int] = None,
    end_time_nano: Optional[int] = None,
    status: Optional[Dict[str, Any]] = None,
    links: Optional[List[Dict[str, Any]]] = None
) -> Dict[str, Any]:
    now_nano = int(time.time() * 1e9)
    s = {
        "traceId": trace_id,
        "spanId": span_id,
        "name": name,
        "kind": kind,
        "startTimeUnixNano": str(start_time_nano or now_nano),
        "endTimeUnixNano": str(end_time_nano or (now_nano + 10_000_000)),
        "attributes": attributes or [],
        "status": status or {}
    }
    if parent_span_id:
        s["parentSpanId"] = parent_span_id
    if links:
        s["links"] = links
    return s


class OTLPBuilder:
    """
    Constructs and maintains the standard OTLP trace payload for an incident run.
    """

    def __init__(self, run_id: str, public_marker: str, trace_id: str, server_parent_span_id: str):
        self.run_id = run_id
        self.public_marker = public_marker
        self.trace_id = trace_id
        self.server_span_id = server_parent_span_id
        self.agent_span_id = generate_span_id()
        self.spans: List[Dict[str, Any]] = []

        # Common base attributes
        self.base_attrs = [
            create_string_attr("ga5.run.id", self.run_id),
            create_string_attr("ga5.public.marker", self.public_marker)
        ]

        # 1. SERVER POST /v2/incidents
        self.server_span = create_span(
            name="POST /v2/incidents",
            kind=2,  # SERVER
            trace_id=self.trace_id,
            span_id=self.server_span_id,
            attributes=list(self.base_attrs)
        )
        self.spans.append(self.server_span)

        # 2. INTERNAL invoke_agent incident-response
        self.agent_span = create_span(
            name="invoke_agent incident-response",
            kind=1,  # INTERNAL
            trace_id=self.trace_id,
            span_id=self.agent_span_id,
            parent_span_id=self.server_span_id,
            attributes=list(self.base_attrs)
        )
        self.spans.append(self.agent_span)

    def add_model_span(self, model_name: str, span_id: str):
        """Adds CLIENT chat incident-plan span."""
        attrs = list(self.base_attrs) + [
            create_string_attr("gen_ai.operation.name", "chat"),
            create_string_attr("gen_ai.request.model", model_name)
        ]
        span = create_span(
            name="chat incident-plan",
            kind=3,  # CLIENT
            trace_id=self.trace_id,
            span_id=span_id,
            parent_span_id=self.agent_span_id,
            attributes=attrs
        )
        self.spans.append(span)

    def add_logical_tool_span(self, tool_name: str, action_id: str, call_id: str, span_id: str) -> Dict[str, Any]:
        """Adds INTERNAL execute_tool <toolName> span."""
        attrs = list(self.base_attrs) + [
            create_string_attr("ga5.action.id", action_id),
            create_string_attr("gen_ai.tool.name", tool_name),
            create_string_attr("gen_ai.tool.call.id", call_id),
            create_string_attr("gen_ai.operation.name", "execute_tool")
        ]
        span = create_span(
            name=f"execute_tool {tool_name}",
            kind=1,  # INTERNAL
            trace_id=self.trace_id,
            span_id=span_id,
            parent_span_id=self.agent_span_id,
            attributes=attrs
        )
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
    ) -> Dict[str, Any]:
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
            span_status = {"code": 2}  # ERROR
            attrs.append(create_string_attr("error.type", "503"))
        elif error_type == "timeout" or status_code == 0:
            span_status = {"code": 2}  # ERROR
            attrs.append(create_string_attr("error.type", "timeout"))
        elif status_code == 200:
            span_status = {"code": 1}  # OK

        span = create_span(
            name=f"POST tool/{tool_name}",
            kind=3,  # CLIENT
            trace_id=self.trace_id,
            span_id=client_span_id,
            parent_span_id=logical_span_id,
            attributes=attrs,
            status=span_status
        )
        self.spans.append(span)
        return span

    def add_incident_join_span(self, linked_logical_spans: List[Dict[str, Any]]):
        """Adds INTERNAL incident.join span linking diagnostic execute_tool spans."""
        links = []
        for s in linked_logical_spans:
            links.append({
                "traceId": s["traceId"],
                "spanId": s["spanId"]
            })
        span = create_span(
            name="incident.join",
            kind=1,  # INTERNAL
            trace_id=self.trace_id,
            span_id=generate_span_id(),
            parent_span_id=self.agent_span_id,
            attributes=list(self.base_attrs),
            links=links
        )
        self.spans.append(span)

    def add_approval_gate_span(self, approval_id: str, receipt_nonce: Optional[str] = None):
        """Adds INTERNAL approval_gate span."""
        attrs = list(self.base_attrs) + [
            create_string_attr("ga5.approval.id", approval_id)
        ]
        if receipt_nonce:
            attrs.append(create_string_attr("ga5.approval.receipt_nonce", receipt_nonce))

        span = create_span(
            name="approval_gate",
            kind=1,  # INTERNAL
            trace_id=self.trace_id,
            span_id=generate_span_id(),
            parent_span_id=self.agent_span_id,
            attributes=attrs
        )
        self.spans.append(span)

    def to_dict(self) -> Dict[str, Any]:
        """Returns the full OTLP JSON structure."""
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
