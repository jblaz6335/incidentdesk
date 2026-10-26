# My IncidentDesk case study

## The problem I chose

My SOC lab could analyze synthetic telemetry and produce a report, but it did not model an analyst's working environment. I wanted to connect detection engineering to the backend concerns that make an investigation application useful: identities, durable processing, recoverable failures, traceable decisions and readable evidence.

## What I built

I built a FastAPI/PostgreSQL backend, a separate Python worker and a React/TypeScript interface. I reused my lab's five MIT-licensed detection rules with attribution, then added evidence IDs and bounded host/identity correlation. I used opaque sessions, Argon2id password hashing and server-side role checks. I built upload validation and canonical duplicate detection, versioned case updates, comments, audit events and Markdown/JSON exports.

I chose a quiet interface with a case queue, readable timeline and detection explanations. I added responsive layouts and automated accessibility checks. I kept synthetic labels visible in the application and reports.

After the core workflow worked, I added optional AI-assisted evidence selection. I deliberately limited the model to choosing known evidence IDs. My application renders the facts from source fields and requires analyst review before saving the draft as a note. The no-AI path remains fully usable.

## What verification taught me

PostgreSQL testing exposed a timezone-handling error in my login throttle that the SQLite test path did not reveal. I corrected timezone conversion and reran the PostgreSQL suite. Browser accessibility checks exposed low-contrast supporting text and ambiguous landmarks; I corrected those before capturing screenshots. I tested worker failures, lease recovery and concurrent claims, rather than relying on a successful demo alone.

My local Docker installation had a stale-socket startup failure. I ran the application against a separate local PostgreSQL instance and retained a Linux Compose CI job, making the verification boundary explicit instead of claiming the Windows Compose launch succeeded.

After updating Docker Desktop on October 26, 2026, I also verified the one-command Compose demo and all three browser scenarios locally on Windows. The earlier Linux Compose CI run passed as well. I kept both stages in my verification record so the documented result reflects what I actually tested.

## Interview talking points

- **Why PostgreSQL for the queue?** I wanted a small reproducible stack. Row locking lets workers claim jobs safely, and the database transaction commits cases, audit records and completion together. I would reconsider a dedicated broker when throughput or scheduling needs justify it.
- **How do I avoid duplicate work?** I hash normalized, sorted, deduplicated event records and enforce uniqueness in the database. The worker also checks its lease before finalization. Overlapping non-identical files remain a documented limitation.
- **How do I handle analyst races?** I lock the case and compare its version. A stale edit returns a conflict. I record before/after values with the actor in the same transaction.
- **What does an alert prove?** It proves a rule matched the supplied records. It does not prove malicious intent or exfiltration. I preserve source IDs and make uncertainty explicit.
- **Why constrain AI this much?** I can validate an ID against evidence. I cannot reliably validate every claim in a free-form model narrative. Selection still needs human review, but factual rendering is deterministic.
- **What would I change before production?** I would add SSO/MFA, account lifecycle controls, HTTPS, a trusted proxy-aware rate limiter, storage quotas, retention controls, tamper-evident audit storage, operational monitoring and broader security testing. I would measure performance and detection quality with an authorized dataset.

## Portfolio summary

I built a security investigation MVP with authenticated roles, validated log ingestion, a durable PostgreSQL worker, evidence-linked case management and audited report exports. I verified failure paths and the browser workflow using synthetic data. I added optional AI-assisted evidence selection with a deterministic fallback and explicit analyst review.

I do not claim customers, production adoption, reduced incident response times, real breach investigation or measured detection accuracy. My [verification record](verification.md) is the source for test results.
