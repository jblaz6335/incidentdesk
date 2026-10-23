"""Generate local-only credentials, build, migrate, seed and start the demo."""

import pathlib
import secrets
import subprocess
import time
import urllib.request

root = pathlib.Path(__file__).resolve().parents[1]
env = root / ".env"
if not env.exists():
    env.write_text(
        "\n".join(
            f"{key}={secrets.token_urlsafe(24)}"
            for key in (
                "POSTGRES_PASSWORD",
                "DEMO_ADMIN_PASSWORD",
                "DEMO_ANALYST_PASSWORD",
            )
        )
        + "\n"
    )
    env.chmod(0o600)
subprocess.run(["docker", "compose", "up", "--build", "-d"], cwd=root, check=True)
for _ in range(90):
    try:
        urllib.request.urlopen("http://localhost:8080/api/health", timeout=2)
        break
    except Exception:
        time.sleep(2)
else:
    raise SystemExit("Demo did not become healthy. Inspect docker compose ps and logs.")
print(
    "IncidentDesk is ready: http://localhost:8080\nUsernames: admin / analyst\nRead the generated .env locally for DEMO_ADMIN_PASSWORD and DEMO_ANALYST_PASSWORD. Do not share or commit it."
)
