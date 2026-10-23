# My verification record

I performed local verification on October 23, 2026. The application ran with native PostgreSQL 17.11 on loopback, FastAPI, the separate worker and the Vite development frontend. Docker Desktop on this Windows host failed during stale-socket startup; I did not verify a local Windows Compose launch.

## Checks

- PostgreSQL backend tests: authentication, all protected routes, CSRF mutations, administrator restrictions, expiry/logout, throttle, malformed/oversize uploads, canonical duplicates, worker failure/retry, expired leases, late-worker rejection, concurrent workers, case transitions, stale edits, reports and constrained drafts.
- Alembic: applied the initial migration to PostgreSQL and checked that model metadata had no pending differences. CI additionally tests downgrade/upgrade on a disposable database.
- Frontend: TypeScript compilation and production build passed. npm audit reported zero known vulnerabilities at verification time.
- Browser: exercised JSONL upload through the worker into a case, changed status, saved a script-like note as text, prepared and reviewed a no-key draft and downloaded a Markdown report. Also exercised search empty states and malformed upload errors.
- Accessibility: axe checks on the dashboard and evidence view, including the 390-pixel mobile view; fixed contrast and duplicate-landmark issues found by those checks. This is not a full manual screen-reader audit.
- Screenshots: captured from the running application using synthetic data. Desktop dashboard/investigation and mobile evidence view are in `docs/screenshots/`.

## Explicit limits

I did not run a live AI model, purchase inference, deploy infrastructure, benchmark large-scale load, assess real-world detection accuracy or perform an independent security audit. Local-provider tests use controlled valid/invalid responses and simulated failures. The no-key draft path was exercised through the UI. The test client emits an upstream Starlette/httpx deprecation warning; tests still run.

GitHub Actions is configured to run PostgreSQL tests, a migration round trip, the frontend build/audit, Docker Compose startup and browser checks. The workflow status is recorded by GitHub; a configured job alone is not evidence that it passed.
