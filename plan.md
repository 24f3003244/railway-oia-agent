# Plan: AI Incident-Response Agent API (`ga5-incident-agent/v2`)

## 1. Overview & Architecture

The objective is to build a compliant, persistent HTTP REST API for an **AI Incident-Response Agent** in Python. The service processes noisy incident transcripts, diagnoses root causes using LLM integration, executes diagnostic and recovery tools via an asynchronous state machine driven by receipt payloads, enforces security policies (approval gates, credential redaction), and generates precise OpenTelemetry (OTLP) traces matching all internal and external actions.

### Key Operational Constraints
- **Response Deadline**: Max 18 seconds per HTTP request. Total verification deadline is 110 seconds.
- **Max Response Size**: 768 KiB (JSON).
- **Idempotency & Conflicts**: Identical `runId` or `receiptId` requests must return stored state without re-calling the AI model or re-executing actions. Mutated payloads for an existing ID must yield **HTTP 409 Conflict**.
- **Security & Privacy**: Zero sensitive leaks (`accessToken`, `privateNote`, authorization credentials). Redact prompts, transcripts, tool inputs/outputs in OTLP spans.

---

## 2. Recommended Tech Stack

- **Framework**: **FastAPI** + **Uvicorn** (Async, high throughput, fast JSON serialization, native Pydantic validation).
- **Database & Persistence**: **SQLite** (via `aiosqlite` or `sqlite3`) or a local JSON state store to maintain persistent runs and audit logs.
- **LLM Integration**: **LiteLLM** or **OpenAI / Anthropic SDK** with JSON mode / Structured Outputs (e.g. `gpt-4o-mini` or `gemini-2.5-flash` for low-latency, low-cost execution within deadline constraints).
- **Hashing & Utilities**: Python's `hashlib` (SHA-256 for `argumentsDigest` and request verification), `uuid` for ID generation, `pydantic` for schema validation.

---

## 3. Core Component Architecture

```
                             ┌───────────────────────────┐
                             │    Grader / Client        │
                             └─────────────┬─────────────┘
                                           │
                    ┌──────────────────────┼──────────────────────┐
                    ▼                      ▼                      ▼
           POST /v2/incidents    POST /v2/incidents/    GET /v2/incidents/
                                  {runId}/receipts            {runId}
                    │                      │                      │
                    └──────────────────────┼──────────────────────┘
                                           │
                                           ▼
                                 ┌───────────────────┐
                                 │ Request Validation│
                                 │   & Conflict Check│
                                 └─────────┬─────────┘
                                           │
                    ┌──────────────────────┴──────────────────────┐
                    ▼                                             ▼
          [New Run Request]                               [Receipt Update]
                    │                                             │
      ┌─────────────┴─────────────┐                 ┌─────────────┴─────────────┐
      │  Sanitize & Prompt Model │                 │   State Machine Advance   │
      └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                    │                                             │
                    ▼                                             ▼
      ┌───────────────────────────┐                 ┌───────────────────────────┐
      │ Diagnostic Dispatch State │                 │ Approval Gate / Retries / │
      │   & OTLP Trace Creation   │                 │   Terminal State Transition│
      └─────────────┬─────────────┘                 └─────────────┬─────────────┘
                    │                                             │
                    └──────────────────────┬──────────────────────┘
                                           │
                                           ▼
                                 ┌───────────────────┐
                                 │ Store State to DB │
                                 └─────────┬─────────┘
                                           │
                                           ▼
                                 ┌───────────────────┐
                                 │   Return JSON     │
                                 └───────────────────┘
```

---

## 4. Detailed Component Design & Implementation Steps

### Phase 1: Data Models & Pydantic Schemas

Define Pydantic models for incoming requests, stored state, dispatches, receipts, and OTLP outputs.

1. **Incident Context Schemas**:
   - `Sensitive`: `accessToken`, `privateNote` (must be stripped from AI prompts and telemetries).
   - `Incident`: `incidentId`, `title`, `service`, `severity`, `transcript`, `allowedRootCauses`.
   - `ToolCatalogEntry`: `name`, `description`, `inputSchema`.
   - `Policy`: `maximumDiagnostics`, `effectTools`, `approvalRequiredFor`, `doNotExport`.
   - `IncidentRequest`: `profile` (must be `"ga5-incident-agent/v2"`), `runId`, `agentName`, `publicMarker`, `sensitive`, `incident`, `toolCatalog`, `policy`.

2. **State & Response Schemas**:
   - `Diagnosis`: `rootCause` (string), `evidence` (list of strings `["ev_..."]`).
   - `Dispatch`: `actionId`, `callId`, `phase` (`"diagnostic"` | `"effect"`), `toolName`, `arguments`, `evidence`, `attempt` (int), `traceparent`, `approvalId` (optional), `approvalNonce` (optional).
   - `ApprovalRequest`: `approvalId`, `actionId`, `toolName`, `argumentsDigest`.
   - `ReceiptOutcome`: `receiptId`, `actionId`, `callId`, `attempt`, `status`, `resultClass`, `nonce`, `errorType`.
   - `ReceiptApproval`: `receiptId`, `approvalId`, `decision`, `nonce`.
   - `RunState`: `runId`, `status` (`"waiting"`, `"completed"`, `"failed"`), `diagnosis`, `chosenEffect`, `suppressed`, `actionLog`, `receiptLog`, `otlp`.

---

### Phase 2: Request Handler & Conflict / Replay Layer

1. **`POST /v2/incidents`**:
   - Validate `profile == "ga5-incident-agent/v2"`. If invalid, return `400` / `422`.
   - Compute deterministic request SHA-256 payload hash (excluding volatile timestamp/headers).
   - Check SQLite DB:
     - If `runId` exists with matching hash -> Return cached JSON immediately (Replay).
     - If `runId` exists with different hash -> Return **409 Conflict**.
     - If `runId` does not exist -> Proceed with new run initialization.

2. **`POST /v2/incidents/{runId}/receipts`**:
   - Check if `runId` exists. If not, return `404 Not Found`.
   - Compute hash of incoming receipt (`receiptId` + body).
   - If `receiptId` already processed with identical body -> Return stored `RunState` JSON.
   - If `receiptId` processed with mutated content -> Return **409 Conflict**.
   - Otherwise, route receipt to State Machine for transition.

3. **`GET /v2/incidents/{runId}`**:
   - Return stored `RunState` JSON or `404 Not Found`.

---

### Phase 3: AI Planner & Diagnostic Formulation

1. **Transcript & Data Sanitization**:
   - Filter evidence lines matching square bracket tags (e.g. `[ev_101] ...`).
   - Exclude the `sensitive` dictionary and treat customer quotes strictly as data (prevent prompt injection).

2. **Model Call (`chat incident-plan`)**:
   - Prompt the LLM using JSON mode / Function calling.
   - Constrain choices:
     - `rootCause`: Exactly one item from `allowedRootCauses`.
     - `evidence`: 2 to 4 valid evidence IDs extracted from transcript lines.
     - `diagnostics`: 1 to `maximumDiagnostics` diagnostic tools from `toolCatalog` with valid `arguments`.
   - Record start & end timestamps for OTLP `CLIENT chat incident-plan` span creation.

3. **Diagnostic Dispatch Generation**:
   - Create stable `actionId` and `callId` (opaque string >= 8 chars).
   - Construct `traceparent`: `00-<traceId>-<spanId>-01` using the tool's CLIENT span ID.
   - Return initial response with `status: "waiting"`, `diagnosis`, and diagnostic `dispatches`.

---

### Phase 4: Receipt State Machine & Policy Engine

1. **Outcome Processing**:
   - **Diagnostic Success (`status: 200`, `resultClass: "diagnosis_confirmed"`)**: Mark diagnostic completed.
   - **Diagnostic 503 Transient Error**: Allow **exactly ONE retry** (`attempt: 2`). Keep `actionId` & `callId`, generate new CLIENT span ID, set `resend_count=1`.
   - **Diagnostic Timeout (`status: 0`, `errorType: "timeout"`)**: Mark diagnostic failed. Suppress dependent effect actions and set run status to `"failed"`.

2. **Effect Selection & Approval Gate**:
   - Once all diagnostic actions succeed, select the recovery effect tool.
   - Compute `argumentsDigest`:
     - Sort dictionary keys recursively.
     - Dump compact JSON (no extra whitespace).
     - Compute lowercase SHA-256 hex digest (`hashlib.sha256(json_bytes).hexdigest()`).
   - If effect `toolName` is present in `policy.approvalRequiredFor`:
     - **Do NOT dispatch effect immediately**.
     - Emit `status: "waiting"`, `dispatches: []`, and `approvals: [{"approvalId": "...", "actionId": "...", "toolName": "...", "argumentsDigest": "..."}]`.
     - Create internal `approval_gate` span.
   - When receipt with `decision: "approved"` is received:
     - Dispatch effect action with matching `approvalId` and `approvalNonce`.
   - When final effect receipt arrives -> Transition run to `"completed"`.

---

### Phase 5: OTLP Telemetry Construction Engine

Build compliant OpenTelemetry JSON matching the required hierarchy:

```
SERVER POST /v2/incidents
└─ INTERNAL invoke_agent incident-response
   ├─ CLIENT chat incident-plan
   ├─ INTERNAL execute_tool <toolName>
   │  └─ CLIENT POST tool/<toolName>
   ├─ INTERNAL incident.join
   └─ INTERNAL approval_gate
```

1. **Span Guidelines & Attributes**:
   - `kind`: `INTERNAL=1`, `SERVER=2`, `CLIENT=3`.
   - Trace ID: 32-character hex string (shared across all spans in the run).
   - Span IDs: 16-character hex strings (unique per span).
   - Mandatory Attributes on ALL Spans: `ga5.run.id`, `ga5.public.marker`.
   - `chat incident-plan` Attributes: `gen_ai.operation.name="chat"`, `gen_ai.request.model="<model-name>"`.
   - `execute_tool` Attributes: `ga5.action.id`, `gen_ai.tool.name`, `gen_ai.tool.call.id`, `gen_ai.operation.name="execute_tool"`.
   - Tool `CLIENT` Span Attributes: `ga5.action.id`, `ga5.attempt` (int), `ga5.receipt.id`, `ga5.receipt.nonce`, `http.request.method="POST"`, `http.request.resend_count` (int = attempt - 1), HTTP status code / `error.type`.
2. **Redaction Enforcer**:
   - Strictly strip `gen_ai.tool.call.arguments`, `gen_ai.tool.call.result`, prompts, sensitive credentials, and transcript content from trace attributes.

---

## 5. Verification & Testing Strategy

1. **Unit & State Machine Tests**:
   - Validate JSON digest computation for approvals.
   - Verify traceparent parsing and span ID parent-child hierarchy generation.
   - Test 503 retry behavior (attempt counter, resend count) and timeout suppression.

2. **Idempotency & Replay Verification**:
   - Re-send identical `POST /v2/incidents` payload -> Expect 200 OK with identical body without invoking LLM.
   - Send `POST /v2/incidents` payload with modified title/severity under same `runId` -> Expect **409 Conflict**.

3. **Security & Redaction Audit**:
   - Assert `accessToken` and `privateNote` never appear anywhere in responses or OTLP JSON.

---

## 6. Project Structure

```
incident_agent/
├── app/
│   ├── __init__.py
│   ├── main.py              # FastAPI entry point & endpoints
│   ├── models.py            # Pydantic schemas (Request, Response, Receipts, OTLP)
│   ├── planner.py           # LLM interaction & transcript parsing
│   ├── state_machine.py     # Receipt processing, retries, approvals & transitions
│   ├── telemetry.py         # OTLP trace builder & attribute redactions
│   ├── utils.py             # SHA-256 digest calculations, W3C traceparent formatting
│   └── database.py          # SQLite persistence layer
├── plan.md                  # This architecture document
├── requirements.txt         # Dependencies (fastapi, uvicorn, pydantic, liteLLM, aiosqlite)
└── README.md
```
