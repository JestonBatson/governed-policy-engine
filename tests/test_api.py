from fastapi.testclient import TestClient

from govpolicy import api


def test_decision_endpoint_emits_a_signed_audit_event(tmp_path, monkeypatch):
    monkeypatch.setenv("AUDIT_SIGNING_KEY", "test-only-key")
    monkeypatch.setenv("AUDIT_LOG_PATH", str(tmp_path / "audit.jsonl"))
    client = TestClient(api.app)
    configured = client.put(
        "/v1/policies",
        json=[
            {
                "id": "read-reports",
                "effect": "allow",
                "actions": ["report.read"],
                "resources": ["report:*"],
                "any_roles": ["analyst"],
            }
        ],
    )
    assert configured.status_code == 200
    response = client.post(
        "/v1/decisions",
        json={
            "actor": {"id": "analyst-7", "roles": ["analyst"]},
            "action": "report.read",
            "resource": "report:quarterly-risk",
        },
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["decision"]["outcome"] == "ALLOW"
    assert api._audit().verify(payload["audit_event"])
