import json

from govpolicy.audit import AuditLog


def test_append_produces_verifiable_event(tmp_path):
    audit = AuditLog(tmp_path / "audit.jsonl", "test-only-key")
    event = audit.append({"action": "report.read", "decision": {"outcome": "ALLOW"}})
    assert audit.verify(event)
    event["action"] = "report.delete"
    assert not audit.verify(event)
    assert json.loads((tmp_path / "audit.jsonl").read_text()) ["event_id"]
