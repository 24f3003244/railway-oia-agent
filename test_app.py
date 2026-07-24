import json
from fastapi.testclient import TestClient
from app.main import app
from app.database import init_db

def test_full_incident_flow():
    init_db()
    with TestClient(app) as client:
        print("--- 1. Testing POST /v2/incidents ---")
        payload = {
            "profile": "ga5-incident-agent/v2",
            "runId": "run_test_001_sample",
            "agentName": "incident-response",
            "publicMarker": "marker_alpha_123",
            "sensitive": {"accessToken": "secret_token_123", "privateNote": "secret_note"},
            "incident": {
                "incidentId": "inc_999",
                "title": "High Latency in Auth Service",
                "service": "auth-service",
                "severity": "SEV-1",
                "transcript": "[ev_101] CPU usage spiked to 98% on pod auth-0\n[ev_102] Database connections exhausted\nCustomer reported 504 errors.",
                "allowedRootCauses": ["database_connection_exhaustion", "memory_leak"]
            },
            "toolCatalog": [
                {"name": "query_metrics", "description": "Fetch metrics", "inputSchema": {}},
                {"name": "rollback_deployment", "description": "Rollback deployment", "inputSchema": {}}
            ],
            "policy": {
                "maximumDiagnostics": 3,
                "effectTools": ["rollback_deployment"],
                "approvalRequiredFor": ["rollback_deployment"],
                "doNotExport": ["sensitive"]
            }
        }

        res1 = client.post("/v2/incidents", json=payload)
        print(f"Status Code: {res1.status_code}")
        print("Response JSON:")
        print(json.dumps(res1.json(), indent=2))
        assert res1.status_code == 200
        res1_json = res1.json()
        assert res1_json["status"] == "waiting"
        assert len(res1_json["dispatches"]) > 0

        action_id = res1_json["dispatches"][0]["actionId"]
        call_id = res1_json["dispatches"][0]["callId"]

        print("\n--- 2. Testing Replay on POST /v2/incidents ---")
        res_replay = client.post("/v2/incidents", json=payload)
        assert res_replay.status_code == 200
        assert res_replay.json() == res1_json
        print("Replay verified successfully!")

        print("\n--- 3. Testing 409 Conflict on POST /v2/incidents ---")
        conflict_payload = dict(payload)
        conflict_payload["publicMarker"] = "marker_mutated"
        res_conflict = client.post("/v2/incidents", json=conflict_payload)
        assert res_conflict.status_code == 409
        print("409 Conflict verified successfully!")

        print("\n--- 4. Testing POST /v2/incidents/{runId}/receipts (Diagnostic Outcome) ---")
        receipt_payload = {
            "receiptId": "receipt_001",
            "outcomes": [{
                "actionId": action_id,
                "callId": call_id,
                "attempt": 1,
                "status": 200,
                "resultClass": "diagnosis_confirmed",
                "nonce": "nonce_uuid_123"
            }]
        }

        res_rec1 = client.post(f"/v2/incidents/{payload['runId']}/receipts", json=receipt_payload)
        print(f"Receipt Response Status: {res_rec1.status_code}")
        print("Receipt Response JSON:")
        print(json.dumps(res_rec1.json(), indent=2))
        assert res_rec1.status_code == 200
        res_rec1_json = res_rec1.json()
        assert len(res_rec1_json.get("approvals", [])) == 1

        appr_id = res_rec1_json["approvals"][0]["approvalId"]

        print("\n--- 5. Testing POST /v2/incidents/{runId}/receipts (Approval Decision) ---")
        appr_receipt_payload = {
            "receiptId": "receipt_002_appr",
            "approvals": [{
                "approvalId": appr_id,
                "decision": "approved",
                "nonce": "nonce_appr_uuid_456"
            }]
        }

        res_appr = client.post(f"/v2/incidents/{payload['runId']}/receipts", json=appr_receipt_payload)
        print(f"Approval Receipt Response Status: {res_appr.status_code}")
        print("Approval Receipt Response JSON:")
        print(json.dumps(res_appr.json(), indent=2))
        assert res_appr.status_code == 200
        res_appr_json = res_appr.json()
        assert len(res_appr_json.get("dispatches", [])) == 1
        effect_action_id = res_appr_json["dispatches"][0]["actionId"]
        effect_call_id = res_appr_json["dispatches"][0]["callId"]

        print("\n--- 6. Testing POST /v2/incidents/{runId}/receipts (Effect Outcome -> Terminal State) ---")
        effect_receipt_payload = {
            "receiptId": "receipt_003_effect",
            "outcomes": [{
                "actionId": effect_action_id,
                "callId": effect_call_id,
                "attempt": 1,
                "status": 200,
                "resultClass": "effect_applied",
                "nonce": "nonce_effect_uuid_789"
            }]
        }

        res_final = client.post(f"/v2/incidents/{payload['runId']}/receipts", json=effect_receipt_payload)
        print(f"Final Response Status: {res_final.status_code}")
        print("Final Response JSON:")
        print(json.dumps(res_final.json(), indent=2))
        assert res_final.status_code == 200
        res_final_json = res_final.json()
        assert res_final_json["status"] == "completed"
        assert "otlp" in res_final_json
        assert len(res_final_json["actionLog"]) >= 2
        assert len(res_final_json["receiptLog"]) >= 3

        print("\n--- 7. Testing GET /v2/incidents/{runId} ---")
        res_get = client.get(f"/v2/incidents/{payload['runId']}")
        assert res_get.status_code == 200
        assert res_get.json() == res_final_json
        print("GET endpoint verified successfully!")

        print("\nALL VERIFICATION TESTS PASSED SUCCESSFULLY!")

if __name__ == "__main__":
    test_full_incident_flow()
