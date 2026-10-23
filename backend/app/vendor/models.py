from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import UTC, datetime
from typing import Any


@dataclass(frozen=True)
class SecurityEvent:
    timestamp: datetime
    event_id: str
    host: str
    channel: str
    username: str = ""
    source_ip: str = ""
    destination_ip: str = ""
    destination_port: int | None = None
    image: str = ""
    command_line: str = ""
    target_path: str = ""
    action: str = ""
    outcome: str = ""
    raw: dict[str, Any] = field(default_factory=dict, compare=False)

    @classmethod
    def from_mapping(cls, payload: dict[str, Any]) -> SecurityEvent:
        raw_timestamp = str(payload["timestamp"]).replace("Z", "+00:00")
        timestamp = datetime.fromisoformat(raw_timestamp)
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=UTC)
        return cls(
            timestamp=timestamp.astimezone(UTC),
            event_id=str(payload.get("event_id", "")),
            host=str(payload.get("host", "")),
            channel=str(payload.get("channel", "")),
            username=str(payload.get("username", "")),
            source_ip=str(payload.get("source_ip", "")),
            destination_ip=str(payload.get("destination_ip", "")),
            destination_port=payload.get("destination_port"),
            image=str(payload.get("image", "")),
            command_line=str(payload.get("command_line", "")),
            target_path=str(payload.get("target_path", "")),
            action=str(payload.get("action", "")),
            outcome=str(payload.get("outcome", "")),
            raw=payload,
        )


@dataclass(frozen=True)
class Finding:
    rule_id: str
    title: str
    severity: str
    description: str
    first_seen: datetime
    last_seen: datetime
    evidence: tuple[str, ...]
    mitre_attack: tuple[str, ...]
    recommended_actions: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        result = asdict(self)
        result["first_seen"] = self.first_seen.isoformat().replace("+00:00", "Z")
        result["last_seen"] = self.last_seen.isoformat().replace("+00:00", "Z")
        return result
