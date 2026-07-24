import os
import json
import logging
import re
from typing import Dict, Any, List, Optional
from openai import AsyncOpenAI
from app.utils import extract_evidence_ids

logger = logging.getLogger(__name__)


async def analyze_incident_with_openai(
    incident_data: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    policy_data: Dict[str, Any],
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Uses OpenAI chat completions to diagnose root cause, select evidence,
    and decide diagnostic/effect tool calls based on tool input schemas.
    """
    allowed_causes = incident_data.get("allowedRootCauses", [])
    transcript = incident_data.get("transcript", "")
    all_evidence = extract_evidence_ids(transcript)

    effect_tool_names = policy_data.get("effectTools", [])
    max_diagnostics = policy_data.get("maximumDiagnostics", 3)

    # Separate diagnostic catalog and effect catalog
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
        "You are an AI Incident-Response Agent (SRE expert).\n"
        "Analyze the incident transcript, identify the single root cause, cite evidence IDs, "
        "and select necessary diagnostic tool calls and one recovery effect call.\n"
        "STRICT REQUIREMENTS:\n"
        "1. rootCause: MUST be exactly one value from allowedRootCauses.\n"
        "2. evidence: MUST be an array of 2 to 4 unique evidence IDs found in the transcript (e.g. ['ev_101', 'ev_102']).\n"
        "3. diagnostics: MUST select 1 to maximumDiagnostics diagnostic calls ONLY from the Diagnostic Tool Catalog. "
        "Arguments MUST strictly conform to the tool's inputSchema and incident context. "
        "Each diagnostic dispatch MUST cite 1 to 4 evidence IDs from the chosen diagnosis evidence array.\n"
        "4. effect: MUST select exactly 1 recovery effect tool from the Effect Tool Catalog. "
        "Arguments MUST strictly conform to the tool's inputSchema.\n"
        "5. Output valid JSON matching the exact schema."
    )

    user_prompt = f"""
Incident Details:
- Title: {incident_data.get('title')}
- Service: {incident_data.get('service')}
- Severity: {incident_data.get('severity')}

Allowed Root Causes (Pick EXACTLY one):
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

Respond in JSON format matching this schema:
{{
  "rootCause": "one value from allowedRootCauses",
  "evidence": ["ev_...", "ev_..."],
  "diagnostics": [
    {{
      "toolName": "name_from_diagnostic_catalog",
      "arguments": {{ ... matching tool inputSchema ... }},
      "evidence": ["ev_..."]
    }}
  ],
  "effect": {{
    "toolName": "name_from_effect_catalog",
    "arguments": {{ ... matching tool inputSchema ... }}
  }}
}}
"""

    model_name = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")

    try:
        response = await client.chat.completions.create(
            model=model_name,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            response_format={"type": "json_object"},
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

        # Ensure diagnostics <= max_diagnostics and uses diagnostic catalog tools
        diag_calls = parsed.get("diagnostics", [])
        valid_diag_names = {t["name"] for t in diagnostic_catalog}
        filtered_diags = []
        for d in diag_calls:
            if d.get("toolName") in valid_diag_names:
                d_ev = [e for e in d.get("evidence", []) if e in cited]
                if not d_ev:
                    d_ev = [cited[0]]
                d["evidence"] = list(dict.fromkeys(d_ev))
                filtered_diags.append(d)

        if not filtered_diags and diagnostic_catalog:
            # Fallback diagnostic tool
            dt = diagnostic_catalog[0]
            filtered_diags.append({
                "toolName": dt["name"],
                "arguments": generate_default_args(dt.get("inputSchema", {}), incident_data),
                "evidence": [cited[0]]
            })

        parsed["diagnostics"] = filtered_diags[:max_diagnostics]

        # Ensure effect uses effect catalog tool
        eff = parsed.get("effect", {})
        valid_eff_names = {t["name"] for t in effect_catalog}
        if eff.get("toolName") not in valid_eff_names and effect_catalog:
            et = effect_catalog[0]
            parsed["effect"] = {
                "toolName": et["name"],
                "arguments": generate_default_args(et.get("inputSchema", {}), incident_data)
            }

        return parsed

    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}. Falling back to heuristic planner.")
        res = fallback_incident_analysis(
            incident_data, diagnostic_catalog, effect_catalog, max_diagnostics, all_evidence
        )
        res["modelName"] = model_name
        return res


def generate_default_args(input_schema: Dict[str, Any], incident_data: Dict[str, Any]) -> Dict[str, Any]:
    """Generates arguments adhering to inputSchema properties."""
    args = {}
    properties = input_schema.get("properties", {})
    service = incident_data.get("service", "default-service")

    for prop_name, prop_spec in properties.items():
        prop_type = prop_spec.get("type", "string")
        if "service" in prop_name:
            args[prop_name] = service
        elif prop_type == "integer" or prop_type == "number":
            args[prop_name] = 1
        elif prop_type == "boolean":
            args[prop_name] = True
        elif prop_type == "array":
            args[prop_name] = [service]
        else:
            args[prop_name] = prop_spec.get("default", service)

    return args


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
        diagnostics.append({
            "toolName": tool["name"],
            "arguments": generate_default_args(tool.get("inputSchema", {}), incident_data),
            "evidence": [evidence[0]]
        })

    chosen_effect_tool = effect_catalog[0] if effect_catalog else {"name": "scale_service", "inputSchema": {}}

    return {
        "rootCause": root_cause,
        "evidence": evidence,
        "diagnostics": diagnostics,
        "effect": {
            "toolName": chosen_effect_tool["name"],
            "arguments": generate_default_args(chosen_effect_tool.get("inputSchema", {}), incident_data)
        },
        "modelName": os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    }
