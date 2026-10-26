# My verification record

I performed local verification on October 23, 2026. The application ran with native PostgreSQL 17.11 on loopback, FastAPI, the separate worker and the Vite development frontend. Docker Desktop on this Windows host failed during stale-socket startup; I did not verify a local Windows Compose launch.

On October 26, 2026, after updating Docker Desktop, I verified the one-command demo on this Windows host with Docker Engine 29.9.2. Compose built the application, applied the migration, seeded the synthetic data and started PostgreSQL, FastAPI, the worker and nginx. The API health check passed at `http://localhost:8080/api/health`. All three Playwright scenarios passed against that local Compose stack, including upload-to-report, the no-key draft/review flow, untrusted notes, malformed uploads, search empty states and desktop/mobile axe checks. I refreshed the screenshots from this run.

## Checks

- PostgreSQL backend tests: **55 passed**, covering authentication, all protected routes, CSRF mutations, administrator restrictions, expiry/logout, throttle, malformed/oversize uploads, canonical duplicates, worker failure/retry, expired leases, late-worker rejection, concurrent workers, case transitions, stale edits, reports and constrained drafts.
- Alembic: applied the initial migration to PostgreSQL and checked that model metadata had no pending differences. CI additionally tests downgrade/upgrade on a disposable database.
- Frontend: TypeScript compilation and production build passed. npm audit reported zero known vulnerabilities at verification time.
- Browser: exercised JSONL upload through the worker into a case, changed status, saved a script-like note as text, prepared and reviewed a no-key draft and downloaded a Markdown report. Also exercised search empty states and malformed upload errors.
- Accessibility: axe checks on the dashboard and evidence view, including the 390-pixel mobile view; fixed contrast and duplicate-landmark issues found by those checks. This is not a full manual screen-reader audit.
- Screenshots: captured from the running application using synthetic data. Desktop dashboard/investigation and mobile evidence view are in `docs/screenshots/`.

## Explicit limits

I did not run a live AI model, purchase inference, deploy infrastructure, benchmark large-scale load, assess real-world detection accuracy or perform an independent security audit. Local-provider tests use controlled valid/invalid responses and simulated failures. The no-key draft path was exercised through the UI. The test client emits an upstream Starlette/httpx deprecation warning; tests still run.

GitHub Actions [run 40001538669](https://github.com/jblaz6335/incidentdesk/actions/runs/40001538669) passed for application commit `ba8286ac317811a8baeed29f6b74cade47016b1c` on October 23, 2026. Both jobs succeeded: the PostgreSQL suite (55 tests), Python dependency audit, migration round trip and metadata check; and the frontend build/audit, Linux Compose startup and three browser scenarios. This record documents the verified application revision; later documentation-only commits do not change that application behavior.
