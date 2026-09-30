from __future__ import annotations

import hashlib
import hmac
import json
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4


class AuditLog:
    def __init__(self, path: str | Path, signing_key: str):
        if not signing_key or signing_key == "replace-me-before-deployment":
            raise ValueError("AUDIT_SIGNING_KEY must be configured")
        self.path = Path(path)
        self.signing_key = signing_key.encode("utf-8")

    def append(self, payload: dict) -> dict:
        event = {"event_id": str(uuid4()), "timestamp": datetime.now(UTC).isoformat(), **payload}
        event["signature"] = self.sign(event)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self.path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps(event, sort_keys=True, separators=(",", ":")) + "\n")
        return event

    def sign(self, event: dict) -> str:
        unsigned = {key: value for key, value in event.items() if key != "signature"}
        body = json.dumps(unsigned, sort_keys=True, separators=(",", ":")).encode("utf-8")
        return hmac.new(self.signing_key, body, hashlib.sha256).hexdigest()

    def verify(self, event: dict) -> bool:
        signature = event.get("signature", "")
        return bool(signature) and hmac.compare_digest(signature, self.sign(event))
