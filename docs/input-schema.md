# My JSONL input contract

I accept UTF-8 JSONL (optionally with a BOM), with one object per line. Trailing blank whitespace is allowed; interior blank lines are invalid. The maximum is 5 MiB and 10,000 non-trailing lines. Duplicate rows within a file collapse during normalization. An entirely empty upload is rejected.

Required fields are `timestamp` (ISO 8601 with timezone), `event_id` (integer or digit string from 0–65535), `host` (1–120 characters) and `channel` (1–200 characters). Event IDs outside the detection set are allowed as context records.

Optional fields: `username`, `source_ip`, `destination_ip`, `destination_port`, `image`, `command_line`, `target_path`, `action`, `outcome`, `logon_type`, `parent_image`, `process_id`, `protocol`. Unknown fields are rejected. Ports must be 0–65535. Username is limited to 120 characters; outcome to 32; other strings default to at most 8,192. IP fields are strings, so malformed addresses can be retained as evidence but won't match the network rule.

```json
{"timestamp":"2026-07-15T09:04:02Z","event_id":4624,"host":"WS-FIN-07","channel":"Security","username":"j.smith","source_ip":"203.0.113.77","outcome":"success"}
```

This example is synthetic. I upload the raw file body to `POST /api/uploads`, with the session cookie, `X-CSRF-Token`, `X-Filename` and optional `X-Synthetic: true` headers. The UI supplies these headers. File extensions are a browser convenience, not a security check; the backend validates the content. Validation errors identify the line without echoing its content. API schema details are available at `/api/docs`.
