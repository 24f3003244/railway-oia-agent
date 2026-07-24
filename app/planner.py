import os
import json
import logging
import re
from typing import Dict, Any, List, Optional
from openai import AsyncOpenAI
from app.utils import extract_evidence_ids

logger = logging.getLogger(__name__)


def validate_and_fix_args(
    args: Dict[str, Any],
    input_schema: Dict[str, Any],
    incident_data: Dict[str, Any]
) -> Dict[str, Any]:
    """Ensures tool arguments conform strictly to input_schema property types and requirements."""
    fixed = dict(args) if isinstance(args, dict) else {}
    properties = input_schema.get("properties", {})
    service = incident_data.get("service", "default-service")

    for prop_name, prop_spec in properties.items():
        prop_type = prop_spec.get("type", "string")
        if prop_name not in fixed or fixed[prop_name] is None:
            if "service" in prop_name.lower():
                fixed[prop_name] = service
            elif prop_type == "integer" or prop_type == "number":
                fixed[prop_name] = 1
            elif prop_type == "boolean":
                fixed[prop_name] = True
            elif prop_type == "array":
                fixed[prop_name] = [service]
            else:
                fixed[prop_name] = prop_spec.get("default", service)

    return fixed


async def analyze_incident_with_openai(
    incident_data: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    policy_data: Dict[str, Any],
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Uses OpenAI chat completions with structured output JSON schema to diagnose root cause,
    select evidence, and decide diagnostic and recovery effect tool calls.
    """
    allowed_causes = incident_data.get("allowedRootCauses", [])
    transcript = incident_data.get("transcript", "")
    all_evidence = extract_evidence_ids(transcript)

    effect_tool_names = policy_data.get("effectTools", [])
    max_diagnostics = policy_data.get("maximumDiagnostics", 3)

    diagnostic_catalog = [t for t in tool_catalog if t["name"] not in effect_tool_names]
    effect_catalog = [t for t in tool_catalog if t["name"] in effect_tool_names]

    if not diagnostic_catalog:
        diagnostic_catalog = tool_catalog
    if not effect_catalog:
        effect_catalog = tool_catalog

    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        logger.warning("No OPENAI_API_KEY found. Using heuristic fallback analysis.")
        return fallback_incident_analysis(
            incident_data, diagnostic_catalog, effect_catalog, max_diagnostics, all_evidence
        )

    client = AsyncOpenAI(api_key=api_key)

    system_prompt = (
        "You are an expert AI Incident-Response Agent (SRE expert).\n"
        "Analyze the incident transcript, identify the single root cause, cite evidence IDs, "
        "and select necessary diagnostic tool calls and one recovery effect call.\n"
        "STRICT CONSTRAINTS:\n"
        "1. rootCause MUST be chosen from allowedRootCauses.\n"
        "2. evidence MUST be an array of 2 to 4 unique evidence IDs present in transcript lines.\n"
        "3. diagnostics: Select 1 to maximumDiagnostics diagnostic tool calls ONLY from Diagnostic Tool Catalog. "
        "Arguments MUST strictly conform to tool inputSchema and incident context. "
        "Each diagnostic call MUST cite 1 to 4 evidence IDs from the chosen diagnosis evidence array.\n"
        "4. effect: Select EXACTLY 1 recovery effect tool from Effect Tool Catalog. "
        "Arguments MUST strictly conform to tool inputSchema."
    )

    user_prompt = f"""
Incident Details:
- Title: {incident_data.get('title')}
- Service: {incident_data.get('service')}
- Severity: {incident_data.get('severity')}

Allowed Root Causes:
{json.dumps(allowed_causes, indent=2)}

Available Evidence IDs in Transcript:
{json.dumps(all_evidence, indent=2)}

Transcript Evidence:
{transcript}

Diagnostic Tool Catalog (Select 1 to {max_diagnostics}):
{json.dumps(diagnostic_catalog, indent=2)}

Effect Tool Catalog (Select EXACTLY 1):
{json.dumps(effect_catalog, indent=2)}

Maximum Diagnostics Allowed: {max_diagnostics}
"""

    model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    json_schema_spec = {
        "name": "incident_analysis",
        "strict": True,
        "schema": {
            "type": "object",
            "properties": {
                "rootCause": {
                    "type": "string",
                    "description": "Selected root cause string from allowedRootCauses."
                },
                "evidence": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Array of 2 to 4 evidence IDs."
                },
                "diagnostics": {
                    "type": "array",
                    "items": {
                        "type": "object",
                        "properties": {
                            "toolName": {"type": "string"},
                            "arguments": {"type": "object"},
                            "evidence": {
                                "type": "array",
                                "items": {"type": "string"}
                            }
                        },
                        "required": ["toolName", "arguments", "evidence"],
                        "additionalProperties": False
                    }
                },
                "effect": {
                    "type": "object",
                    "properties": {
                        "toolName": {"type": "string"},
                        "arguments": {"type": "object"}
                    },
                    "required": ["toolName", "arguments"],
                    "additionalProperties": False
                }
            },
            "required": ["rootCause", "evidence", "diagnostics", "effect"],
            "additionalProperties": False
        }
    }

    try:
        response = await client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_schema", "json_schema": json_schema_spec},
            temperature=0.1
        )

        content = response.choices[0].message.content
        parsed = json.loads(content)
        parsed["modelName"] = model_name

        # Post-validation & cleanup
        if parsed.get("rootCause") not in allowed_causes and allowed_causes:
            parsed["rootCause"] = allowed_causes[0]

        cited = [e for e in parsed.get("evidence", []) if e in all_evidence]
        if len(cited) < 2:
            cited = all_evidence[:min(4, max(2, len(all_evidence)))] if all_evidence else ["ev_1", "ev_2"]
        elif len(cited) > 4:
            cited = cited[:4]
        parsed["evidence"] = cited

        diag_calls = parsed.get("diagnostics", [])
        diagnostic_map = {t["name"]: t for t in diagnostic_catalog}
        filtered_diags = []

        for d in diag_calls:
            tool_name = d.get("toolName")
            if tool_name in diagnostic_map:
                schema = diagnostic_map[tool_name].get("inputSchema", {})
                d["arguments"] = validate_and_fix_args(d.get("arguments", {}), schema, incident_data)
                
                d_ev = [e for e in d.get("evidence", []) if e in cited]
                if not d_ev:
                    d_ev = [cited[0]]
                d["evidence"] = list(dict.fromkeys(d_ev))
                filtered_diags.append(d)

        if not filtered_diags and diagnostic_catalog:
            dt = diagnostic_catalog[0]
            filtered_diags.append({
                "toolName": dt["name"],
                "arguments": validate_and_fix_args({}, dt.get("inputSchema", {}), incident_data),
                "evidence": [cited[0]]
            })

        parsed["diagnostics"] = filtered_diags[:max_diagnostics]

        eff = parsed.get("effect", {})
        effect_map = {t["name"]: t for t in effect_catalog}
        eff_name = eff.get("toolName")
        if eff_name in effect_map:
            schema = effect_map[eff_name].get("inputSchema", {})
            eff["arguments"] = validate_and_fix_args(eff.get("arguments", {}), schema, incident_data)
        elif effect_catalog:
            et = effect_catalog[0]
            eff = {
                "toolName": et["name"],
                "arguments": validate_and_fix_args({}, et.get("inputSchema", {}), incident_data)
            }

        parsed["effect"] = eff
        return parsed

    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}. Falling back to heuristic planner.")
        res = fallback_incident_analysis(
            incident_data, diagnostic_catalog, effect_catalog, max_diagnostics, all_evidence
        )
        res["modelName"] = model_name
        return res


def fallback_incident_analysis(
    incident_data: Dict[str, Any],
    diagnostic_catalog: List[Dict[str, Any]],
    effect_catalog: List[Dict[str, Any]],
    max_diagnostics: int,
    all_evidence: List[str]
) -> Dict[str, Any]:
    """Fallback heuristic analyzer."""
    allowed_causes = incident_data.get("allowedRootCauses", [])
    root_cause = allowed_causes[0] if allowed_causes else "unknown_failure"

    evidence = all_evidence[:min(4, max(2, len(all_evidence)))] if all_evidence else ["ev_1", "ev_2"]

    diagnostics = []
    for tool in diagnostic_catalog[:max_diagnostics]:
        schema = tool.get("inputSchema", {})
        diagnostics.append({
            "toolName": tool["name"],
            "arguments": validate_and_fix_args({}, schema, incident_data),
            "evidence": [evidence[0]]
        })

    chosen_effect_tool = effect_catalog[0] if effect_catalog else {"name": "scale_service", "inputSchema": {}}

    return {
        "rootCause": root_cause,
        "evidence": evidence,
        "diagnostics": diagnostics,
        "effect": {
            "toolName": chosen_effect_tool["name"],
            "arguments": validate_and_fix_args({}, chosen_effect_tool.get("inputSchema", {}), incident_data)
        },
        "modelName": os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    }
