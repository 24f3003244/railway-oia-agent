import os
import logging
from contextlib import asynccontextmanager
from typing import Optional
from fastapi import FastAPI, Request, HTTPException, Header, Response, status
from fastapi.responses import JSONResponse

from app.models import IncidentRequest, ReceiptRequest
from app.utils import compute_payload_hash
from app.database import (
    init_db, get_run, save_run, get_receipt, save_receipt
)
from app.state_machine import (
    create_new_incident_run, process_receipt_and_advance, build_final_response
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup logic
    init_db()
    logger.info("SQLite database initialized successfully.")
    yield
    # Shutdown logic


app = FastAPI(
    title="AI Incident-Response Agent API",
    version="2.0.0",
    lifespan=lifespan
)


@app.get("/")
async def root():
    return {
        "service": "ga5-incident-agent",
        "version": "v2",
        "status": "online"
    }


@app.post("/v2/incidents")
async def handle_create_incident(
    req: IncidentRequest,
    request: Request,
    traceparent: Optional[str] = Header(None)
):
    """
    POST /v2/incidents - Receives incident payload, validates profile, runs AI diagnosis,
    formulates initial diagnostic dispatches, and returns initial response.
    """
    # 1. Profile Validation
    if req.profile != "ga5-incident-agent/v2":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported profile '{req.profile}'. Expected 'ga5-incident-agent/v2'."
        )

    run_id = req.runId
    body_bytes = await request.body()
    payload_hash = compute_payload_hash(req.model_dump())

    # 2. Check for Replay or Conflict
    existing_run = get_run(run_id)
    if existing_run:
        saved_hash, saved_state = existing_run
        if saved_hash == payload_hash:
            # Replay existing state without re-running AI model or actions
            logger.info(f"Replay detected for runId={run_id}. Returning cached state.")
            response_payload = saved_state.get("last_response_payload")
            if not response_payload:
                response_payload = build_final_response(saved_state, saved_state.get("status", "waiting"))
            return JSONResponse(content=response_payload)
        else:
            # Conflict: same runId with changed content
            logger.warning(f"Conflict detected for runId={run_id}. Payload hash mismatch.")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Run ID '{run_id}' already exists with different payload content."
            )

    # 3. Process New Incident Run
    api_key = os.environ.get("OPENAI_API_KEY")
    internal_state, response_payload = await create_new_incident_run(
        req=req,
        incoming_traceparent=traceparent,
        api_key=api_key
    )

    # Save state to DB
    internal_state["last_response_payload"] = response_payload
    save_run(run_id, payload_hash, internal_state)

    return JSONResponse(content=response_payload)


@app.post("/v2/incidents/{runId}/receipts")
async def handle_incident_receipt(
    runId: str,
    receipt_req: ReceiptRequest
):
    """
    POST /v2/incidents/{runId}/receipts - Processes tool outcomes and approvals.
    """
    existing_run = get_run(runId)
    if not existing_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident runId '{runId}' not found."
        )

    saved_hash, internal_state = existing_run
    receipt_id = receipt_req.receiptId
    receipt_payload_hash = compute_payload_hash(receipt_req.model_dump())

    # Check for Receipt Replay or Conflict
    existing_receipt = get_receipt(receipt_id)
    if existing_receipt:
        rec_run_id, rec_hash = existing_receipt
        if rec_hash == receipt_payload_hash:
            logger.info(f"Replay detected for receiptId={receipt_id}. Returning current state.")
            response_payload = internal_state.get("last_response_payload")
            if not response_payload:
                response_payload = build_final_response(internal_state, internal_state.get("status", "waiting"))
            return JSONResponse(content=response_payload)
        else:
            logger.warning(f"Conflict detected for receiptId={receipt_id}. Payload mismatch.")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Receipt ID '{receipt_id}' already exists with different payload content."
            )

    # Advance State Machine
    updated_state, response_payload = process_receipt_and_advance(internal_state, receipt_req)
    updated_state["last_response_payload"] = response_payload

    # Persist updated state and receipt record
    save_run(runId, saved_hash, updated_state)
    save_receipt(receipt_id, runId, receipt_payload_hash)

    return JSONResponse(content=response_payload)


@app.get("/v2/incidents/{runId}")
async def handle_get_incident(runId: str):
    """
    GET /v2/incidents/{runId} - Returns the current stored state of the run.
    """
    existing_run = get_run(runId)
    if not existing_run:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Incident runId '{runId}' not found."
        )

    _, internal_state = existing_run
    response_payload = internal_state.get("last_response_payload")
    if not response_payload:
        response_payload = build_final_response(internal_state, internal_state.get("status", "waiting"))

    return JSONResponse(content=response_payload)
