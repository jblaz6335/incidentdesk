import json
import hashlib
from datetime import datetime
from pydantic import BaseModel, ConfigDict, Field, AwareDatetime, ValidationError

class Event(BaseModel):
    model_config = ConfigDict(extra='forbid', str_max_length=8192)
    timestamp: AwareDatetime
    event_id: str | int
    host: str = Field(min_length=1, max_length=120)
    channel: str = Field(min_length=1, max_length=200)
    username: str = Field(default='', max_length=120)
    source_ip: str = ''
    destination_ip: str = ''
    destination_port: int | None = Field(default=None, ge=0, le=65535)
    image: str = ''
    command_line: str = ''
    target_path: str = ''
    action: str = ''
    outcome: str = ''
    logon_type: int | None = None
    parent_image: str = ''
    process_id: int | None = None
    protocol: str = ''

def parse_logs(raw: bytes):
    try:
        lines = raw.decode('utf-8-sig').splitlines()
    except UnicodeDecodeError:
        raise ValueError('Upload must be UTF-8 JSONL.')
    if not lines or len(lines) > 10000:
        raise ValueError('Provide 1–10,000 JSONL records.')
    events = []
    for i, line in enumerate(lines, 1):
        try:
            item = Event.model_validate_json(line).model_dump(mode='json')
            item['event_id'] = str(item['event_id'])
            # Normalize offsets, key order, record order and duplicate records for deduplication.
            from datetime import timezone
            item['timestamp'] = datetime.fromisoformat(item['timestamp'].replace('Z', '+00:00')).astimezone(timezone.utc).isoformat()
            events.append(item)
        except (ValidationError, ValueError):
            raise ValueError(f'Line {i}: invalid event. Require timezone-aware timestamp, event_id, host and channel; unknown fields are rejected.') from None
    canonical = sorted(set(json.dumps(e, sort_keys=True, separators=(',', ':')) for e in events))
    digest = hashlib.sha256('\n'.join(canonical).encode()).hexdigest()
    return [json.loads(e) for e in canonical], digest
