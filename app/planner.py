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
    maximum_diagnostics: int,
    api_key: Optional[str] = None
) -> Dict[str, Any]:
    """
    Uses OpenAI chat completions to diagnose root cause, select evidence,
    and decide diagnostic/effect tool calls.
    """
    allowed_causes = incident_data.get("allowedRootCauses", [])
    transcript = incident_data.get("transcript", "")
    all_evidence = extract_evidence_ids(transcript)

    if not api_key:
        api_key = os.environ.get("OPENAI_API_KEY")

    if not api_key:
        logger.warning("No OPENAI_API_KEY found. Using heuristic fallback analysis.")
        return fallback_incident_analysis(incident_data, tool_catalog, maximum_diagnostics, all_evidence)

    client = AsyncOpenAI(api_key=api_key)

    system_prompt = (
        "You are an expert site reliability engineering (SRE) AI agent. "
        "Your task is to analyze noisy incident transcripts, determine the single most likely root cause, "
        "cite 2 to 4 evidence IDs found in the transcript, choose 1 to 3 diagnostic tool calls, "
        "and choose 1 primary recovery effect tool call.\n"
        "RULES:\n"
        "1. rootCause MUST be exactly one of the allowed root causes provided.\n"
        "2. evidence MUST be a array of 2 to 4 exact evidence IDs present in transcript (e.g. ['ev_1', 'ev_2']).\n"
        "3. Choose 1 to maximumDiagnostics diagnostic tool calls from toolCatalog.\n"
        "4. Choose 1 recovery effect tool call.\n"
        "5. Output valid JSON matching the exact schema specified."
    )

    user_prompt = f"""
Incident Details:
- Title: {incident_data.get('title')}
- Service: {incident_data.get('service')}
- Severity: {incident_data.get('severity')}

Allowed Root Causes: {json.dumps(allowed_causes)}
Available Evidence IDs in Transcript: {json.dumps(all_evidence)}

Transcript:
{transcript}

Tool Catalog:
{json.dumps(tool_catalog)}

Maximum Diagnostic Calls Allowed: {maximum_diagnostics}

Respond with JSON format:
{{
  "rootCause": "one allowed value",
  "evidence": ["ev_...", "ev_..."],
  "diagnostics": [
    {{
      "toolName": "name_from_catalog",
      "arguments": {{...}},
      "evidence": ["ev_..."]
    }}
  ],
  "effect": {{
    "toolName": "name_from_catalog",
    "arguments": {{...}}
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

        # Ensure evidence valid and 2..4 elements
        cited = [e for e in parsed.get("evidence", []) if e in all_evidence]
        if len(cited) < 2:
            cited = all_evidence[:min(4, max(2, len(all_evidence)))]
        elif len(cited) > 4:
            cited = cited[:4]
        parsed["evidence"] = cited

        # Ensure diagnostics <= maximum_diagnostics
        diag_calls = parsed.get("diagnostics", [])
        if len(diag_calls) > maximum_diagnostics:
            parsed["diagnostics"] = diag_calls[:maximum_diagnostics]

        # Ensure diagnostic evidence cites from diagnosis evidence
        for d in parsed.get("diagnostics", []):
            d_ev = [e for e in d.get("evidence", []) if e in cited]
            if not d_ev:
                d_ev = [cited[0]]
            d["evidence"] = list(dict.fromkeys(d_ev))  # unique

        return parsed

    except Exception as e:
        logger.error(f"OpenAI API call failed: {e}. Falling back to heuristic planner.")
        res = fallback_incident_analysis(incident_data, tool_catalog, maximum_diagnostics, all_evidence)
        res["modelName"] = model_name
        return res


def fallback_incident_analysis(
    incident_data: Dict[str, Any],
    tool_catalog: List[Dict[str, Any]],
    maximum_diagnostics: int,
    all_evidence: List[str]
) -> Dict[str, Any]:
    """Fallback heuristic analyzer if OpenAI API is unavailable or fails."""
    allowed_causes = incident_data.get("allowedRootCauses", [])
    root_cause = allowed_causes[0] if allowed_causes else "unknown_failure"

    evidence = all_evidence[:min(4, max(2, len(all_evidence)))] if all_evidence else ["ev_1", "ev_2"]

    diagnostic_tools = [t for t in tool_catalog if "query" in t["name"] or "check" in t["name"] or "get" in t["name"]]
    if not diagnostic_tools:
        diagnostic_tools = tool_catalog[:1]

    diagnostics = []
    for tool in diagnostic_tools[:maximum_diagnostics]:
        diagnostics.append({
            "toolName": tool["name"],
            "arguments": {"service": incident_data.get("service", "default"), "query": "incident_root_cause"},
            "evidence": [evidence[0]]
        })

    effect_tools = [t for t in tool_catalog if t not in diagnostic_tools]
    if not effect_tools:
        effect_tools = tool_catalog[-1:] if tool_catalog else [{"name": "scale_service", "inputSchema": {}}]
    
    chosen_effect_tool = effect_tools[0]

    return {
        "rootCause": root_cause,
        "evidence": evidence,
        "diagnostics": diagnostics,
        "effect": {
            "toolName": chosen_effect_tool["name"],
            "arguments": {"service": incident_data.get("service", "default"), "action": "recover"}
        },
        "modelName": os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
    }
