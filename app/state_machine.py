import logging
from typing import Dict, Any, List, Optional, Tuple
from app.models import (
    IncidentRequest, ReceiptRequest, compute_arguments_digest
)
from app.planner import analyze_incident_with_openai
from app.telemetry import OTLPBuilder
from app.utils import (
    generate_trace_id, generate_span_id, generate_opaque_id,
    parse_traceparent, format_traceparent
)

logger = logging.getLogger(__name__)


async def create_new_incident_run(
    req: IncidentRequest,
    incoming_traceparent: Optional[str] = None,
    api_key: Optional[str] = None
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Initializes a new incident run: parses traceparent, calls OpenAI model planner,
    formulates initial diagnostic dispatches, and creates OTLP trace structure.
    """
    trace_id, server_span_id = parse_traceparent(incoming_traceparent)
    model_span_id = generate_span_id()

    # Instantiate OTLP Builder
    otlp = OTLPBuilder(
        run_id=req.runId,
        public_marker=req.publicMarker,
        trace_id=trace_id,
        server_parent_span_id=server_span_id
    )

    # Convert tool catalog to list of dicts for planner
    tool_catalog_list = [t.model_dump() for t in req.toolCatalog]

    # Call AI Model Planner
    analysis = await analyze_incident_with_openai(
        incident_data=req.incident.model_dump(),
        tool_catalog=tool_catalog_list,
        maximum_diagnostics=req.policy.maximumDiagnostics,
        api_key=api_key
    )

    # Record model span in OTLP
    otlp.add_model_span(
        model_name=analysis.get("modelName", "gpt-4o-mini"),
        span_id=model_span_id
    )

    diagnosis = {
        "rootCause": analysis.get("rootCause"),
        "evidence": analysis.get("evidence", [])
    }

    # Formulate Diagnostic Dispatches
    dispatches = []
    action_log = []
    diagnostic_span_tracking = []

    for d_spec in analysis.get("diagnostics", []):
        tool_name = d_spec["toolName"]
        action_id = generate_opaque_id("act")
        call_id = generate_opaque_id("call")
        logical_span_id = generate_span_id()
        client_span_id = generate_span_id()
        dispatch_traceparent = format_traceparent(trace_id, client_span_id)

        cited_ev = d_spec.get("evidence", [])
        if not cited_ev:
            cited_ev = diagnosis["evidence"][:1]

        dispatch_item = {
            "actionId": action_id,
            "callId": call_id,
            "phase": "diagnostic",
            "toolName": tool_name,
            "arguments": d_spec.get("arguments", {}),
            "evidence": cited_ev,
            "attempt": 1,
            "traceparent": dispatch_traceparent
        }

        # Add logical tool span to OTLP
        logical_span = otlp.add_logical_tool_span(
            tool_name=tool_name,
            action_id=action_id,
            call_id=call_id,
            span_id=logical_span_id
        )

        dispatches.append(dispatch_item)
        action_log.append(dispatch_item)

        diagnostic_span_tracking.append({
            "actionId": action_id,
            "callId": call_id,
            "toolName": tool_name,
            "logicalSpanId": logical_span_id,
            "clientSpanId": client_span_id,
            "logicalSpan": logical_span
        })

    internal_state = {
        "runId": req.runId,
        "status": "waiting",
        "publicMarker": req.publicMarker,
        "traceId": trace_id,
        "serverSpanId": server_span_id,
        "diagnosis": diagnosis,
        "policy": req.policy.model_dump(),
        "toolCatalog": tool_catalog_list,
        "plannedEffect": analysis.get("effect"),
        "dispatches": dispatches,
        "approvals": [],
        "actionLog": action_log,
        "receiptLog": [],
        "diagnosticTracking": diagnostic_span_tracking,
        "pendingApproval": None,
        "chosenEffect": None,
        "suppressed": [],
        "otlpData": otlp.to_dict()
    }

    response_payload = {
        "runId": req.runId,
        "status": "waiting",
        "diagnosis": diagnosis,
        "dispatches": dispatches,
        "approvals": []
    }

    return internal_state, response_payload


def process_receipt_and_advance(
    internal_state: Dict[str, Any],
    receipt_req: ReceiptRequest
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    """
    Processes incoming outcome or approval receipts and transitions run state.
    Returns (updated_internal_state, response_payload).
    """
    otlp_data = internal_state.get("otlpData", {"resourceSpans": [{"scopeSpans": [{"spans": []}]}]})
    spans_list = otlp_data["resourceSpans"][0]["scopeSpans"][0]["spans"]
    
    receipt_log = internal_state.get("receiptLog", [])
    action_log = internal_state.get("actionLog", [])
    diagnostic_tracking = internal_state.get("diagnosticTracking", [])
    policy = internal_state.get("policy", {})

    trace_id = internal_state["traceId"]
    agent_span_id = spans_list[1]["spanId"] if len(spans_list) > 1 else generate_span_id()
    public_marker = internal_state["publicMarker"]
    run_id = internal_state["runId"]

    base_attrs = [
        {"key": "ga5.run.id", "value": {"stringValue": run_id}},
        {"key": "ga5.public.marker", "value": {"stringValue": public_marker}}
    ]

    # Helper to add physical span directly to spans_list
    def add_physical_tool_span(tool_name, action_id, logical_span_id, client_span_id, attempt, receipt_id=None, nonce=None, status_code=200, error_type=None):
        attrs = list(base_attrs) + [
            {"key": "ga5.action.id", "value": {"stringValue": action_id}},
            {"key": "ga5.attempt", "value": {"intValue": str(attempt)}},
            {"key": "http.request.method", "value": {"stringValue": "POST"}},
            {"key": "http.request.resend_count", "value": {"intValue": str(max(0, attempt - 1))}}
        ]
        if receipt_id:
            attrs.append({"key": "ga5.receipt.id", "value": {"stringValue": receipt_id}})
        if nonce:
            attrs.append({"key": "ga5.receipt.nonce", "value": {"stringValue": nonce}})

        span_status = {}
        if status_code == 503:
            span_status = {"code": 2}
            attrs.append({"key": "error.type", "value": {"stringValue": "503"}})
        elif error_type == "timeout" or status_code == 0:
            span_status = {"code": 2}
            attrs.append({"key": "error.type", "value": {"stringValue": "timeout"}})
        elif status_code == 200:
            span_status = {"code": 1}

        span = {
            "traceId": trace_id,
            "spanId": client_span_id,
            "parentSpanId": logical_span_id,
            "name": f"POST tool/{tool_name}",
            "kind": 3,
            "startTimeUnixNano": "1700000000000000000",
            "endTimeUnixNano": "1700000000010000000",
            "attributes": attrs,
            "status": span_status
        }
        spans_list.append(span)

    # 1. Process Outcome Receipts
    if receipt_req.outcomes:
        for outcome in receipt_req.outcomes:
            r_log_item = {
                "receiptId": receipt_req.receiptId,
                "actionId": outcome.actionId,
                "callId": outcome.callId,
                "attempt": outcome.attempt,
                "status": outcome.status,
                "resultClass": outcome.resultClass,
                "nonce": outcome.nonce
            }
            if outcome.errorType:
                r_log_item["errorType"] = outcome.errorType
            receipt_log.append(r_log_item)

            matching_dt = next((d for d in diagnostic_tracking if d["actionId"] == outcome.actionId), None)
            if matching_dt:
                add_physical_tool_span(
                    tool_name=matching_dt["toolName"],
                    action_id=outcome.actionId,
                    logical_span_id=matching_dt["logicalSpanId"],
                    client_span_id=matching_dt["clientSpanId"],
                    attempt=outcome.attempt,
                    receipt_id=receipt_req.receiptId,
                    nonce=outcome.nonce,
                    status_code=outcome.status,
                    error_type=outcome.errorType
                )

                if outcome.status == 503 and outcome.attempt == 1:
                    new_client_span_id = generate_span_id()
                    matching_dt["clientSpanId"] = new_client_span_id
                    retry_traceparent = format_traceparent(trace_id, new_client_span_id)

                    retry_dispatch = {
                        "actionId": outcome.actionId,
                        "callId": outcome.callId,
                        "phase": "diagnostic",
                        "toolName": matching_dt["toolName"],
                        "arguments": next((a["arguments"] for a in action_log if a["actionId"] == outcome.actionId), {}),
                        "evidence": internal_state["diagnosis"]["evidence"][:1],
                        "attempt": 2,
                        "traceparent": retry_traceparent
                    }
                    action_log.append(retry_dispatch)

                    response_payload = {
                        "runId": internal_state["runId"],
                        "status": "waiting",
                        "diagnosis": internal_state["diagnosis"],
                        "dispatches": [retry_dispatch],
                        "approvals": []
                    }
                    internal_state["receiptLog"] = receipt_log
                    internal_state["actionLog"] = action_log
                    return internal_state, response_payload

                if outcome.status == 0 or outcome.errorType == "timeout":
                    internal_state["status"] = "failed"
                    internal_state["suppressed"] = [internal_state.get("plannedEffect", {}).get("toolName", "effect_tool")]
                    response_payload = build_final_response(internal_state, status="failed")
                    return internal_state, response_payload

            pending_effect = internal_state.get("pendingEffectDispatch")
            if pending_effect and pending_effect["actionId"] == outcome.actionId:
                if outcome.status == 200:
                    internal_state["status"] = "completed"
                    internal_state["chosenEffect"] = pending_effect["toolName"]
                    response_payload = build_final_response(internal_state, status="completed")
                    return internal_state, response_payload
                else:
                    internal_state["status"] = "failed"
                    response_payload = build_final_response(internal_state, status="failed")
                    return internal_state, response_payload

    # 2. Process Approval Receipts
    if receipt_req.approvals:
        for app in receipt_req.approvals:
            receipt_log.append({
                "receiptId": receipt_req.receiptId,
                "approvalId": app.approvalId,
                "decision": app.decision,
                "nonce": app.nonce
            })

            pending_app = internal_state.get("pendingApproval")
            if pending_app and pending_app["approvalId"] == app.approvalId:
                if app.decision == "approved":
                    # Add approval gate span
                    appr_span = {
                        "traceId": trace_id,
                        "spanId": generate_span_id(),
                        "parentSpanId": agent_span_id,
                        "name": "approval_gate",
                        "kind": 1,
                        "startTimeUnixNano": "1700000000000000000",
                        "endTimeUnixNano": "1700000000010000000",
                        "attributes": list(base_attrs) + [
                            {"key": "ga5.approval.id", "value": {"stringValue": app.approvalId}},
                            {"key": "ga5.approval.receipt_nonce", "value": {"stringValue": app.nonce}}
                        ],
                        "status": {}
                    }
                    spans_list.append(appr_span)

                    effect_spec = internal_state.get("plannedEffect", {})
                    tool_name = effect_spec.get("toolName", "scale_service")
                    action_id = pending_app["actionId"]
                    call_id = generate_opaque_id("call_eff")
                    logical_span_id = generate_span_id()
                    client_span_id = generate_span_id()
                    traceparent = format_traceparent(trace_id, client_span_id)

                    effect_dispatch = {
                        "actionId": action_id,
                        "callId": call_id,
                        "phase": "effect",
                        "toolName": tool_name,
                        "arguments": effect_spec.get("arguments", {}),
                        "evidence": internal_state["diagnosis"]["evidence"][:1],
                        "attempt": 1,
                        "traceparent": traceparent,
                        "approvalId": app.approvalId,
                        "approvalNonce": app.nonce
                    }
                    action_log.append(effect_dispatch)
                    internal_state["pendingEffectDispatch"] = effect_dispatch

                    logical_span = {
                        "traceId": trace_id,
                        "spanId": logical_span_id,
                        "parentSpanId": agent_span_id,
                        "name": f"execute_tool {tool_name}",
                        "kind": 1,
                        "startTimeUnixNano": "1700000000000000000",
                        "endTimeUnixNano": "1700000000010000000",
                        "attributes": list(base_attrs) + [
                            {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                            {"key": "gen_ai.tool.name", "value": {"stringValue": tool_name}},
                            {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                            {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                        ],
                        "status": {}
                    }
                    spans_list.append(logical_span)

                    diagnostic_tracking.append({
                        "actionId": action_id,
                        "callId": call_id,
                        "toolName": tool_name,
                        "logicalSpanId": logical_span_id,
                        "clientSpanId": client_span_id,
                        "logicalSpan": logical_span
                    })

                    response_payload = {
                        "runId": internal_state["runId"],
                        "status": "waiting",
                        "diagnosis": internal_state["diagnosis"],
                        "dispatches": [effect_dispatch],
                        "approvals": []
                    }
                    internal_state["receiptLog"] = receipt_log
                    internal_state["actionLog"] = action_log
                    return internal_state, response_payload

    # 3. Check Diagnostic Completion & Issue Effect or Approval Request
    if not internal_state.get("diagnosticsJoined", False):
        original_action_ids = [d["actionId"] for d in diagnostic_tracking if d.get("actionId")]
        successful_action_ids = set()
        for r in receipt_log:
            if r.get("status") == 200 and r.get("resultClass") == "diagnosis_confirmed":
                successful_action_ids.add(r.get("actionId"))

        if all(aid in successful_action_ids for aid in original_action_ids):
            internal_state["diagnosticsJoined"] = True

            # Add incident.join span linking diagnostic spans
            links = [{"traceId": d["logicalSpan"]["traceId"], "spanId": d["logicalSpan"]["spanId"]} for d in diagnostic_tracking if "logicalSpan" in d]
            join_span = {
                "traceId": trace_id,
                "spanId": generate_span_id(),
                "parentSpanId": agent_span_id,
                "name": "incident.join",
                "kind": 1,
                "startTimeUnixNano": "1700000000000000000",
                "endTimeUnixNano": "1700000000010000000",
                "attributes": list(base_attrs),
                "status": {},
                "links": links
            }
            spans_list.append(join_span)

            planned_effect = internal_state.get("plannedEffect") or {"toolName": "scale_service", "arguments": {}}
            effect_tool_name = planned_effect.get("toolName", "scale_service")
            approval_required_list = policy.get("approvalRequiredFor", [])

            if effect_tool_name in approval_required_list:
                approval_id = generate_opaque_id("appr")
                reserved_action_id = generate_opaque_id("act_eff")
                digest = compute_arguments_digest(planned_effect.get("arguments", {}))

                approval_req_obj = {
                    "approvalId": approval_id,
                    "actionId": reserved_action_id,
                    "toolName": effect_tool_name,
                    "argumentsDigest": digest
                }
                internal_state["pendingApproval"] = approval_req_obj

                # Add approval gate span
                appr_span = {
                    "traceId": trace_id,
                    "spanId": generate_span_id(),
                    "parentSpanId": agent_span_id,
                    "name": "approval_gate",
                    "kind": 1,
                    "startTimeUnixNano": "1700000000000000000",
                    "endTimeUnixNano": "1700000000010000000",
                    "attributes": list(base_attrs) + [
                        {"key": "ga5.approval.id", "value": {"stringValue": approval_id}}
                    ],
                    "status": {}
                }
                spans_list.append(appr_span)

                response_payload = {
                    "status": "waiting",
                    "dispatches": [],
                    "approvals": [approval_req_obj]
                }
                internal_state["receiptLog"] = receipt_log
                internal_state["actionLog"] = action_log
                return internal_state, response_payload
            else:
                action_id = generate_opaque_id("act_eff")
                call_id = generate_opaque_id("call_eff")
                logical_span_id = generate_span_id()
                client_span_id = generate_span_id()
                traceparent = format_traceparent(trace_id, client_span_id)

                effect_dispatch = {
                    "actionId": action_id,
                    "callId": call_id,
                    "phase": "effect",
                    "toolName": effect_tool_name,
                    "arguments": planned_effect.get("arguments", {}),
                    "evidence": internal_state["diagnosis"]["evidence"][:1],
                    "attempt": 1,
                    "traceparent": traceparent
                }
                action_log.append(effect_dispatch)
                internal_state["pendingEffectDispatch"] = effect_dispatch

                logical_span = {
                    "traceId": trace_id,
                    "spanId": logical_span_id,
                    "parentSpanId": agent_span_id,
                    "name": f"execute_tool {effect_tool_name}",
                    "kind": 1,
                    "startTimeUnixNano": "1700000000000000000",
                    "endTimeUnixNano": "1700000000010000000",
                    "attributes": list(base_attrs) + [
                        {"key": "ga5.action.id", "value": {"stringValue": action_id}},
                        {"key": "gen_ai.tool.name", "value": {"stringValue": effect_tool_name}},
                        {"key": "gen_ai.tool.call.id", "value": {"stringValue": call_id}},
                        {"key": "gen_ai.operation.name", "value": {"stringValue": "execute_tool"}}
                    ],
                    "status": {}
                }
                spans_list.append(logical_span)

                diagnostic_tracking.append({
                    "actionId": action_id,
                    "callId": call_id,
                    "toolName": effect_tool_name,
                    "logicalSpanId": logical_span_id,
                    "clientSpanId": client_span_id,
                    "logicalSpan": logical_span
                })

                response_payload = {
                    "runId": internal_state["runId"],
                    "status": "waiting",
                    "diagnosis": internal_state["diagnosis"],
                    "dispatches": [effect_dispatch],
                    "approvals": []
                }
                internal_state["receiptLog"] = receipt_log
                internal_state["actionLog"] = action_log
                return internal_state, response_payload

    internal_state["receiptLog"] = receipt_log
    internal_state["actionLog"] = action_log
    response_payload = build_final_response(internal_state, status=internal_state.get("status", "waiting"))
    return internal_state, response_payload


def build_final_response(internal_state: Dict[str, Any], status: str) -> Dict[str, Any]:
    """Formats terminal final response or stored GET state."""
    otlp_data = internal_state.get("otlpData", {"resourceSpans": [{"scopeSpans": [{"spans": []}]}]})
    return {
        "runId": internal_state["runId"],
        "status": status,
        "diagnosis": internal_state["diagnosis"],
        "chosenEffect": internal_state.get("chosenEffect") or internal_state.get("plannedEffect", {}).get("toolName", "scale_service"),
        "suppressed": internal_state.get("suppressed", []),
        "actionLog": internal_state.get("actionLog", []),
        "receiptLog": internal_state.get("receiptLog", []),
        "otlp": otlp_data
    }
