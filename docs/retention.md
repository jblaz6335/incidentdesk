# My retention and deletion policy

IncidentDesk stores validated, normalized event JSON in PostgreSQL. It does not keep a separate uploaded file on disk. The original byte stream is discarded after validation; the normalized payload and canonical hash are retained.

I do not silently expire evidence in this MVP. Input, cases, comments and audit records persist in the named PostgreSQL volume until an explicit administrative action or operator-managed database removal.

- An administrator can select **Delete input** for a completed or failed upload. This clears its retained input payload and records the actor and action in the global audit log. Queued or processing uploads cannot be purged.
- Deleting input does **not** delete case evidence, findings, notes, audit entries, metadata or the duplicate hash. A deleted failed input cannot be retried. Reuploading the same normalized content is still a duplicate.
- There is no per-case erasure endpoint or configured retention schedule. I would need a documented evidence-preservation and deletion policy before adding those to a deployed service.
- `docker compose down` stops/removes containers but preserves the data volume. `docker compose down -v` permanently removes this demo's database volume, including all accounts, cases and audit data. I use that command only when I intend to reset the disposable demo. Separately retained exports and backups are not affected.
- Logs and reports can contain sensitive information. I use synthetic data for demonstrations and do not commit real investigations, credentials or exports. Operators are responsible for local file permissions, volume encryption, backups and deleting downloaded reports.

Session records expire after eight hours; expired sessions are removed on later successful logins. Login-throttle rows are reused per source and are not automatically purged. This bounded local-demo approach is not a complete enterprise retention system.
