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
    trace_id, parent_span_id = parse_traceparent(incoming_traceparent)
    server_span_id = generate_span_id()
    model_span_id = generate_span_id()

    # Instantiate OTLP Builder
    otlp = OTLPBuilder(
        run_id=req.runId,
        public_marker=req.publicMarker,
        trace_id=trace_id,
        server_span_id=server_span_id,
        parent_span_id=parent_span_id
    )

    tool_catalog_list = [t.model_dump() for t in req.toolCatalog]
    policy_dict = req.policy.model_dump()

    # Call AI Model Planner passing policy to isolate diagnostic tools vs effect tools
    analysis = await analyze_incident_with_openai(
        incident_data=req.incident.model_dump(),
        tool_catalog=tool_catalog_list,
        policy_data=policy_dict,
        api_key=api_key
    )

    # Record exactly one chat incident-plan span in OTLP
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
    diagnostic_tracking = []

    for d_spec in analysis.get("diagnostics", []):
        tool_name = d_spec["toolName"]
        action_id = generate_opaque_id("act_diag")
        call_id = generate_opaque_id("call_diag")
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
        otlp.add_logical_tool_span(
            tool_name=tool_name,
            action_id=action_id,
            call_id=call_id,
            span_id=logical_span_id
        )

        dispatches.append(dispatch_item)
        action_log.append(dispatch_item)

        diagnostic_tracking.append({
            "actionId": action_id,
            "callId": call_id,
            "toolName": tool_name,
            "logicalSpanId": logical_span_id,
            "clientSpanId": client_span_id,
            "phase": "diagnostic"
        })

    internal_state = {
        "runId": req.runId,
        "status": "waiting",
        "publicMarker": req.publicMarker,
        "traceId": trace_id,
        "serverSpanId": server_span_id,
        "parentSpanId": parent_span_id,
        "agentSpanId": otlp.agent_span_id,
        "diagnosis": diagnosis,
        "policy": policy_dict,
        "toolCatalog": tool_catalog_list,
        "plannedEffect": analysis.get("effect"),
        "dispatches": dispatches,
        "approvals": [],
        "actionLog": action_log,
        "receiptLog": [],
        "diagnosticTracking": diagnostic_tracking,
        "pendingApproval": None,
        "pendingEffectDispatch": None,
        "chosenEffect": None,
        "suppressed": [],
        "otlpBuilder": otlp
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
    otlp: OTLPBuilder = internal_state["otlpBuilder"]
    receipt_log = internal_state.get("receiptLog", [])
    action_log = internal_state.get("actionLog", [])
    diagnostic_tracking = internal_state.get("diagnosticTracking", [])
    policy = internal_state.get("policy", {})

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
                # Add physical tool CLIENT span to OTLP
                otlp.add_physical_tool_client_span(
                    tool_name=matching_dt["toolName"],
                    action_id=outcome.actionId,
                    logical_span_id=matching_dt["logicalSpanId"],
                    client_span_id=matching_dt["clientSpanId"],
                    attempt=outcome.attempt,
                    receipt_id=receipt_req.receiptId,
                    receipt_nonce=outcome.nonce,
                    status_code=outcome.status,
                    result_class=outcome.resultClass,
                    error_type=outcome.errorType
                )

                # Check 503 retry condition (exactly one retry allowed)
                if outcome.status == 503 and outcome.attempt == 1:
                    new_client_span_id = generate_span_id()
                    matching_dt["clientSpanId"] = new_client_span_id
                    retry_traceparent = format_traceparent(internal_state["traceId"], new_client_span_id)

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

                # Check Timeout condition
                if outcome.status == 0 or outcome.errorType == "timeout":
                    internal_state["status"] = "failed"
                    planned_eff_name = internal_state.get("plannedEffect", {}).get("toolName", "effect_tool")
                    internal_state["suppressed"] = [planned_eff_name]
                    internal_state["chosenEffect"] = None

                    internal_state["receiptLog"] = receipt_log
                    internal_state["actionLog"] = action_log
                    response_payload = build_final_response(internal_state, status="failed")
                    return internal_state, response_payload

            # Check if this was an effect outcome receipt
            pending_effect = internal_state.get("pendingEffectDispatch")
            if pending_effect and pending_effect["actionId"] == outcome.actionId:
                internal_state["receiptLog"] = receipt_log
                internal_state["actionLog"] = action_log
                if outcome.status == 200:
                    internal_state["status"] = "completed"
                    internal_state["chosenEffect"] = pending_effect["toolName"]
                    internal_state["suppressed"] = []
                    response_payload = build_final_response(internal_state, status="completed")
                    return internal_state, response_payload
                else:
                    internal_state["status"] = "failed"
                    internal_state["chosenEffect"] = None
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
                    otlp.add_approval_gate_span(approval_id=app.approvalId, receipt_nonce=app.nonce)

                    effect_spec = internal_state.get("plannedEffect", {})
                    tool_name = effect_spec.get("toolName", "scale_service")
                    action_id = pending_app["actionId"]  # reserve same action ID
                    call_id = generate_opaque_id("call_eff")
                    logical_span_id = generate_span_id()
                    client_span_id = generate_span_id()
                    traceparent = format_traceparent(internal_state["traceId"], client_span_id)

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

                    otlp.add_logical_tool_span(
                        tool_name=tool_name,
                        action_id=action_id,
                        call_id=call_id,
                        span_id=logical_span_id
                    )

                    diagnostic_tracking.append({
                        "actionId": action_id,
                        "callId": call_id,
                        "toolName": tool_name,
                        "logicalSpanId": logical_span_id,
                        "clientSpanId": client_span_id,
                        "phase": "effect"
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
        diag_entries = [d for d in diagnostic_tracking if d.get("phase") == "diagnostic"]
        original_action_ids = [d["actionId"] for d in diag_entries]
        successful_action_ids = set()
        for r in receipt_log:
            if r.get("status") == 200 and r.get("resultClass") == "diagnosis_confirmed":
                successful_action_ids.add(r.get("actionId"))

        if original_action_ids and all(aid in successful_action_ids for aid in original_action_ids):
            internal_state["diagnosticsJoined"] = True

            # Add incident.join span linking all diagnostic logical spans if fan out (>1)
            logical_span_ids = [d["logicalSpanId"] for d in diag_entries]
            if len(logical_span_ids) > 1:
                otlp.add_incident_join_span(logical_span_ids)

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
                otlp.add_approval_gate_span(approval_id=approval_id)

                response_payload = {
                    "runId": internal_state["runId"],
                    "status": "waiting",
                    "diagnosis": internal_state["diagnosis"],
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
                traceparent = format_traceparent(internal_state["traceId"], client_span_id)

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

                otlp.add_logical_tool_span(
                    tool_name=effect_tool_name,
                    action_id=action_id,
                    call_id=call_id,
                    span_id=logical_span_id
                )

                diagnostic_tracking.append({
                    "actionId": action_id,
                    "callId": call_id,
                    "toolName": effect_tool_name,
                    "logicalSpanId": logical_span_id,
                    "clientSpanId": client_span_id,
                    "phase": "effect"
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
    otlp: OTLPBuilder = internal_state["otlpBuilder"]
    res = {
        "runId": internal_state["runId"],
        "status": status,
        "diagnosis": internal_state["diagnosis"],
        "chosenEffect": internal_state.get("chosenEffect"),
        "suppressed": internal_state.get("suppressed", []),
        "actionLog": internal_state.get("actionLog", []),
        "receiptLog": internal_state.get("receiptLog", []),
        "otlp": otlp.to_dict()
    }
    if status == "completed" and not res.get("chosenEffect"):
        res["chosenEffect"] = internal_state.get("plannedEffect", {}).get("toolName", "scale_service")
    elif status == "failed":
        res["chosenEffect"] = None
    return res
