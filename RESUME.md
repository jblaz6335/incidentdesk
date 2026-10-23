# IncidentDesk — paused checkpoint

I paused this build on October 23, 2026 for a Windows update. This is unfinished source, not a verified MVP. Nothing has been published to GitHub.

## My requested scope

I am building a solo portfolio project for GitHub account `jblaz6335`: FastAPI, PostgreSQL migrations, React/TypeScript, a background worker, Docker Compose and GitHub Actions. Documentation must use my solo developer voice and make only verified claims. I want secure analyst/admin accounts, validated JSONL uploads, deduplication, correlated cases, an evidence timeline, comments, audit history, report exports, synthetic seed data and a one-command demo. Optional evidence-cited AI drafting comes only after the core MVP works. No automatic containment or paid infrastructure.

## Saved work

- Inspected my SOC lab at https://github.com/jblaz6335/soc-incident-investigation-lab, commit `c53542720f2aae6e555647d97911416dd35f5053`.
- Copied its MIT-licensed detection and model modules into `backend/app/vendor/`, with the original license, and synthetic telemetry into `data/synthetic-events.jsonl`.
- Drafted database models, opaque cookie sessions with Argon2 password hashing and CSRF checks, role checks, upload validation, canonical deduplication, a leased database worker, case correlation, case changes, comments, audit records and Markdown/JSON reports.
- Drafted backend dependencies, migration environment, seed command, Compose services and demo script.
- Drafted frontend package/configuration and nginx/Docker configuration. The React application and CSS have NOT been written yet.

## Important unverified state

No application tests, migrations, frontend build, running UI or full workflow have been verified. The initial Alembic revision still needs to be written. The frontend has no source entry point or npm lockfile yet, so Docker builds cannot succeed yet. Backend implementation needs review and testing, including concurrent worker behavior, authentication, validation, and error handling. The optional AI feature is not implemented.

## Resume work

1. Read workspace guidance and this checkpoint. Preserve my solo developer voice.
2. Check Docker after the Windows update. The CLI exists, but the Linux engine pipe was unavailable despite launching Docker Desktop. Do not claim Compose was tested.
3. Complete the migration, polished accessible React interface and integration tests. Verify every protected operation, malformed and oversize uploads, duplicates, worker failures/lease recovery, transitions and upload-to-report behavior against PostgreSQL.
4. Run Compose, inspect desktop/mobile UI and capture real screenshots. Add optional constrained AI drafting only after core verification; cite evidence IDs, require analyst review and remain functional without a key.
5. Write README, architecture, threat model, attribution, retention/deletion policy, design decisions, limitations, portfolio case study and interview notes based on actual results. Preserve the lab's disclosure that bundled telemetry is synthetic, addresses use documentation ranges and no malware is executed.
6. Add CI, run checks, review secrets/untrusted input boundaries and publish the completed repository if authentication still permits.

## Local environment

The repository is under `outputs/incidentdesk/` in this chat's workspace. The inspected lab is under `work/soc-lab/`. A Python environment was created under `work/venv/`; installation of `backend/requirements.txt` was started before pausing. GitHub CLI authenticated as `jblaz6335` with repository/workflow permissions. No credentials were copied into source. No `.env` was generated and no database was seeded.

I read the Sites local-development and preview guidance. This project uses the explicitly requested Python/PostgreSQL stack locally and is intended for GitHub publication, not Sites hosting. Available browser automation is `mcp__cua_repl`. No browser QA has started. No subagents were spawned.
