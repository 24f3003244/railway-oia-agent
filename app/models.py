import hashlib
import json
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field


class Sensitive(BaseModel):
    accessToken: Optional[str] = None
    privateNote: Optional[str] = None


class Incident(BaseModel):
    incidentId: str
    title: str
    service: str
    severity: str
    transcript: str
    allowedRootCauses: List[str]


class ToolCatalogEntry(BaseModel):
    name: str
    description: str
    inputSchema: Dict[str, Any] = Field(default_factory=dict)


class Policy(BaseModel):
    maximumDiagnostics: int = 3
    effectTools: List[str] = Field(default_factory=list)
    approvalRequiredFor: List[str] = Field(default_factory=list)
    doNotExport: List[str] = Field(default_factory=list)


class IncidentRequest(BaseModel):
    profile: str
    runId: str
    agentName: str = "incident-response"
    publicMarker: str
    sensitive: Optional[Sensitive] = None
    incident: Incident
    toolCatalog: List[ToolCatalogEntry]
    policy: Policy


class Diagnosis(BaseModel):
    rootCause: str
    evidence: List[str]


class Dispatch(BaseModel):
    actionId: str
    callId: str
    phase: str  # "diagnostic" | "effect"
    toolName: str
    arguments: Dict[str, Any]
    evidence: List[str]
    attempt: int = 1
    traceparent: str
    approvalId: Optional[str] = None
    approvalNonce: Optional[str] = None


class ApprovalRequest(BaseModel):
    approvalId: str
    actionId: str
    toolName: str
    argumentsDigest: str


class OutcomeItem(BaseModel):
    actionId: str
    callId: str
    attempt: int
    status: int
    resultClass: Optional[str] = None
    errorType: Optional[str] = None
    nonce: str


class ApprovalItem(BaseModel):
    approvalId: str
    decision: str  # "approved" | "rejected"
    nonce: str


class ReceiptRequest(BaseModel):
    receiptId: str
    outcomes: Optional[List[OutcomeItem]] = None
    approvals: Optional[List[ApprovalItem]] = None


def compute_arguments_digest(arguments: Dict[str, Any]) -> str:
    """
    Computes SHA-256 over recursively key-sorted compact JSON arguments.
    """
    compact_json = json.dumps(arguments, sort_keys=True, separators=(',', ':'))
    return hashlib.sha256(compact_json.encode('utf-8')).hexdigest()
