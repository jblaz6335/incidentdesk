# My threat model

I designed IncidentDesk as a local portfolio MVP for one trusted team. I have not deployed it to production, performed an independent penetration test or established regulatory compliance.

| Asset / trust boundary | Threat | My control | Remaining limit |
| --- | --- | --- | --- |
| Browser → API | Anonymous access or role spoofing | Server-side session lookup and role dependencies on every protected route | No SSO, MFA or account recovery UI |
| Session cookie | Theft or CSRF | Argon2id passwords, hashed opaque sessions, eight-hour expiry, logout revocation, HttpOnly/SameSite cookies, CSRF header on mutations | Local demo is HTTP; deployment needs HTTPS and Secure cookies |
| Login | Password guessing | Generic failure, dummy hash for unknown users, database throttle | No distributed edge limiter; shared proxy IP can throttle legitimate users |
| Uploaded telemetry | Resource exhaustion / malformed input | 5 MiB body cap, 10,000 rows, field bounds, strict schema, nginx cap | No total storage quota; a trusted account can submit many distinct jobs |
| Evidence/comments → UI/export | Stored script or markup injection | React text rendering, no raw HTML renderer, production CSP, escaped Markdown, attachment exports | Exported logs remain untrusted data; downstream tools must treat them accordingly |
| API → database | SQL injection | SQLAlchemy parameter binding | Database operator remains trusted |
| Parallel uploads/workers | Duplicate cases or partial writes | Canonical unique hash, row locks, lease check, atomic case/audit/completion commit | Overlapping non-identical uploads are not globally deduplicated |
| Concurrent analysts | Lost decisions | Version check and row lock | No realtime conflict merge |
| Audit trail | Silent edits | No edit/delete audit endpoint; actor and before/after values recorded | Database owners can alter records; no cryptographic or WORM audit store |
| Evidence → optional local model | Prompt injection / invented claims | Local-host allowlist, fixed schema, known-ID validation, deterministic fact rendering, no tools or actions | A model can omit or poorly prioritize evidence; analyst review is essential |
| Files and credentials | Accidental disclosure | Generated ignored `.env`, no source secrets, no access/payload logging, sanitized worker/provider errors | Local filesystem and volume encryption/backups are the operator's responsibility |

I expose only the frontend on `127.0.0.1:8080` in Compose. PostgreSQL, FastAPI and the worker stay on the Compose network. I do not allow the upload to specify a filesystem path, run commands, fetch URLs found in logs, or execute containment. User-provided filenames are normalized and used only as metadata.

I tested authorization denials for every protected operation, CSRF denials for every mutation, administrator restrictions, expiry/logout, malformed/oversize uploads, deduplication, worker failure and recovery, concurrent worker claims, transition conflicts, report escaping and script-like analyst notes. Those checks establish specific behaviors; they do not establish that the entire application is vulnerability-free.
