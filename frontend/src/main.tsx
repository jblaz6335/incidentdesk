import React, { useEffect, useState } from "react";
import { createRoot } from "react-dom/client";
import {
  Shield,
  LayoutDashboard,
  UploadCloud,
  History,
  Users,
  ArrowUpRight,
  ArrowLeft,
  Search,
  FileText,
  LogOut,
  CheckCircle2,
  AlertTriangle,
  Activity,
  ChevronRight,
  RefreshCw,
} from "lucide-react";
import "./style.css";

type User = { id: number; username: string; role: string };
type Case = {
  id: number;
  title: string;
  host: string;
  username: string;
  severity: string;
  status: string;
  assignee_id: number | null;
  version: number;
  synthetic: boolean;
  finding_count: number;
  evidence_count: number;
  created: string;
};
type Evidence = Record<string, string | number | null> & {
  evidence_id: string;
  timestamp: string;
  event_id: string;
};
type Finding = {
  rule_id: string;
  title: string;
  description: string;
  severity: string;
  mitre_attack: string[];
  evidence_ids: string[];
};
type Entry = {
  id: number;
  actor: string;
  kind: string;
  detail: string;
  created: string;
};
type Detail = Case & {
  evidence: Evidence[];
  findings: Finding[];
  activities: Entry[];
};
type Upload = {
  id: number;
  filename: string;
  status: string;
  event_count: number;
  synthetic: boolean;
  error: string | null;
  attempts: number;
  payload_retained: boolean;
};
let csrf = "";
async function api<T>(path: string, options: RequestInit = {}): Promise<T> {
  const response = await fetch("/api" + path, {
    ...options,
    headers: {
      "Content-Type": "application/json",
      "X-CSRF-Token": csrf,
      ...options.headers,
    },
  });
  if (!response.ok) {
    const body = await response
      .json()
      .catch(() => ({
        detail: `Request failed (${response.status}). Please try again.`,
      }));
    throw new Error(
      typeof body.detail === "string"
        ? body.detail
        : "Check the supplied fields and try again.",
    );
  }
  return response.json();
}
const date = (s: string) =>
  new Date(s).toLocaleString(undefined, {
    month: "short",
    day: "numeric",
    hour: "2-digit",
    minute: "2-digit",
  });
const label = (s: string) => s.replaceAll("_", " ");
function Badge({ value }: { value: string }) {
  return <span className={"badge " + value}>{label(value)}</span>;
}

function App() {
  const [user, setUser] = useState<User | null>(null),
    [loading, setLoading] = useState(true),
    [page, setPage] = useState("cases");
  const [error, setError] = useState(""),
    [notice, setNotice] = useState(""),
    [busy, setBusy] = useState(false);
  const [cases, setCases] = useState<Case[]>([]),
    [uploads, setUploads] = useState<Upload[]>([]),
    [users, setUsers] = useState<User[]>([]),
    [audit, setAudit] = useState<Entry[]>([]);
  const [selected, setSelected] = useState<Detail | null>(null),
    [tab, setTab] = useState("evidence");
  const [search, setSearch] = useState(""),
    [severity, setSeverity] = useState(""),
    [status, setStatus] = useState(""),
    [assignee, setAssignee] = useState("");
  const [file, setFile] = useState<File | null>(null),
    [synthetic, setSynthetic] = useState(true),
    [comment, setComment] = useState("");
  const [draft, setDraft] = useState<{
    text: string;
    source: string;
    review_required: boolean;
  } | null>(null);
  const act = async (fn: () => Promise<void>) => {
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await fn();
    } catch (e) {
      setError((e as Error).message);
    } finally {
      setBusy(false);
    }
  };
  async function refresh() {
    const [c, u, people] = await Promise.all([
      api<Case[]>("/cases"),
      api<Upload[]>("/uploads"),
      api<User[]>("/users"),
    ]);
    setCases(c);
    setUploads(u);
    setUsers(people);
  }
  useEffect(() => {
    api<{ user: User; csrf: string }>("/auth/me")
      .then((r) => {
        csrf = r.csrf;
        setUser(r.user);
      })
      .catch(() => {})
      .finally(() => setLoading(false));
  }, []);
  useEffect(() => {
    if (!user) return;
    refresh().catch((e) => setError(e.message));
    const id = setInterval(() => refresh().catch(() => {}), 4000);
    return () => clearInterval(id);
  }, [user]);
  async function openCase(id: number) {
    setSelected(await api<Detail>("/cases/" + id));
    setPage("cases");
    setTab("evidence");
    setDraft(null);
    setError("");
    window.scrollTo(0, 0);
  }
  async function patch(values: Record<string, unknown>) {
    if (!selected) return;
    await api("/cases/" + selected.id, {
      method: "PATCH",
      body: JSON.stringify({ version: selected.version, ...values }),
    });
    setSelected(await api<Detail>("/cases/" + selected.id));
    await refresh();
    setNotice("Case updated. Change recorded in the audit trail.");
  }
  async function navigate(next: string) {
    setPage(next);
    setSelected(null);
    setError("");
    setNotice("");
    if (next === "audit") setAudit(await api<Entry[]>("/audit"));
  }
  const visible = cases.filter(
    (c) =>
      (!search || c.title.toLowerCase().includes(search.toLowerCase())) &&
      (!severity || c.severity === severity) &&
      (!status || c.status === status) &&
      (!assignee ||
        (assignee === "unassigned"
          ? c.assignee_id === null
          : String(c.assignee_id) === assignee)),
  );
  if (loading)
    return <main className="loading">Opening investigation workspace…</main>;
  if (!user)
    return (
      <div className="login">
        <section className="login-story">
          <div className="brand">
            <Shield /> IncidentDesk<span> / </span>
          </div>
          <div>
            <p className="eyebrow">SECURITY OPERATIONS · SOLO PROJECT</p>
            <h1>
              From signal
              <br />
              to a defensible
              <br />
              <em>investigation.</em>
            </h1>
            <p>
              A focused workspace for tracing evidence, investigating rule
              matches, and documenting what you know.
            </p>
          </div>
          <small>Built by jblaz6335 · Synthetic demonstration data</small>
        </section>
        <main className="login-form">
          <div className="login-card">
            <span className="mini-icon">
              <Shield />
            </span>
            <h2>Welcome back.</h2>
            <p className="muted">Sign in to your investigation workspace.</p>
            {error && (
              <div role="alert" className="error">
                {error}
              </div>
            )}
            <form
              onSubmit={(e) => {
                e.preventDefault();
                const data = new FormData(e.currentTarget);
                void act(async () => {
                  const r = await api<{ user: User; csrf: string }>(
                    "/auth/login",
                    {
                      method: "POST",
                      body: JSON.stringify(Object.fromEntries(data)),
                    },
                  );
                  csrf = r.csrf;
                  setUser(r.user);
                });
              }}
            >
              <label>
                Username
                <input
                  autoComplete="username"
                  name="username"
                  required
                  autoFocus
                />
              </label>
              <label>
                Password
                <input
                  type="password"
                  autoComplete="current-password"
                  name="password"
                  required
                />
              </label>
              <button className="primary" disabled={busy}>
                Sign in <ArrowUpRight size={17} />
              </button>
            </form>
            <div className="hint">
              <Shield size={18} />
              <span>
                Local demo accounts: <strong>analyst</strong> and{" "}
                <strong>admin</strong>. Use the passwords generated in your
                local <code>.env</code> file.
              </span>
            </div>
          </div>
        </main>
      </div>
    );
  return (
    <div className="shell">
      <a className="skip" href="#main">
        Skip to main content
      </a>
      <aside className="sidebar" aria-label="Workspace navigation">
        <div className="brand">
          <Shield /> IncidentDesk<span> / </span>
        </div>
        <p className="nav-label">WORKSPACE</p>
        <nav aria-label="Main navigation">
          {[
            ["cases", "Investigations", LayoutDashboard],
            ["uploads", "Log uploads", UploadCloud],
            ...(user.role === "administrator"
              ? [
                  ["users", "Accounts", Users],
                  ["audit", "Audit log", History],
                ]
              : []),
          ].map(([id, title, Icon]) => {
            const I = Icon as typeof Shield;
            return (
              <button
                key={String(id)}
                className={page === id ? "active" : ""}
                onClick={() => void act(() => navigate(String(id)))}
              >
                <I size={18} />
                {String(title)}
                {id === "cases" && (
                  <span className="nav-count">{cases.length}</span>
                )}
              </button>
            );
          })}
        </nav>
        <div className="sidebar-bottom">
          <div className="demo-mark">
            <span className="dot" /> LOCAL WORKSPACE
          </div>
          <p>
            Evidence first.
            <br />
            Human decisions, always.
          </p>
          <div className="profile">
            <span className="avatar">
              {user.username.slice(0, 2).toUpperCase()}
            </span>
            <div>
              <strong>{user.username}</strong>
              <small>{user.role}</small>
            </div>
            <button
              aria-label="Sign out"
              title="Sign out"
              onClick={() =>
                void act(async () => {
                  await api("/auth/logout", { method: "POST" });
                  setUser(null);
                  setSelected(null);
                  csrf = "";
                })
              }
            >
              <LogOut size={17} />
            </button>
          </div>
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <span>
            Workspace <ChevronRight size={14} />{" "}
            <strong>
              {selected
                ? `Case #${selected.id}`
                : page === "cases"
                  ? "Investigations"
                  : label(page)}
            </strong>
          </span>
          <span className="top-note">
            <span className="dot" /> Analyst review required
          </span>
        </header>
        <main id="main">
          <div className="disclosure">
            <Shield size={16} />
            <span>
              <strong>Portfolio demo</strong> · Bundled telemetry is synthetic.
              Rule matches are leads, not proof of compromise.
            </span>
          </div>
          {error && (
            <div className="error" role="alert">
              {error}
              <button aria-label="Dismiss error" onClick={() => setError("")}>
                ×
              </button>
            </div>
          )}
          {notice && (
            <div className="success" role="status">
              {notice}
            </div>
          )}
          {page === "cases" && !selected && (
            <>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">TRIAGE & INVESTIGATE</p>
                  <h1>Investigations</h1>
                  <p className="muted">
                    Follow the evidence. Keep every decision accountable.
                  </p>
                </div>
                <button
                  className="primary"
                  onClick={() => void act(() => navigate("uploads"))}
                >
                  <UploadCloud size={17} /> Upload logs
                </button>
              </div>
              <section className="metrics" aria-label="Case summary">
                {[
                  [
                    "Active cases",
                    cases.filter((c) =>
                      ["open", "investigating"].includes(c.status),
                    ).length,
                    "Awaiting or under review",
                  ],
                  [
                    "Critical priority",
                    cases.filter(
                      (c) =>
                        c.severity === "critical" &&
                        !["resolved", "closed"].includes(c.status),
                    ).length,
                    "Active critical cases",
                  ],
                  [
                    "Unassigned",
                    cases.filter((c) => c.assignee_id === null).length,
                    "Ready for an analyst",
                  ],
                  [
                    "Resolved / closed",
                    cases.filter((c) =>
                      ["resolved", "closed"].includes(c.status),
                    ).length,
                    "Documented investigations",
                  ],
                ].map(([title, n, sub], i) => (
                  <div className="metric" key={title}>
                    <span>{title}</span>
                    <strong className={i === 1 ? "critical-text" : ""}>
                      {n}
                      <span className="metric-icon">
                        {i === 3 ? <CheckCircle2 /> : <Activity />}
                      </span>
                    </strong>
                    <small>{sub}</small>
                  </div>
                ))}
              </section>
              <section className="panel">
                <div className="panel-title">
                  <h2>
                    Case queue <span className="count">{visible.length}</span>
                  </h2>
                  <span className="muted small">
                    Auto-refreshes every 4 seconds
                  </span>
                </div>
                <div className="filters">
                  <label className="search">
                    <Search size={17} />
                    <input
                      aria-label="Search cases"
                      placeholder="Search host or identity…"
                      value={search}
                      onChange={(e) => setSearch(e.target.value)}
                    />
                  </label>
                  <select
                    aria-label="Filter severity"
                    value={severity}
                    onChange={(e) => setSeverity(e.target.value)}
                  >
                    <option value="">All severities</option>
                    {["critical", "high", "medium", "low"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                  <select
                    aria-label="Filter status"
                    value={status}
                    onChange={(e) => setStatus(e.target.value)}
                  >
                    <option value="">All statuses</option>
                    {["open", "investigating", "resolved", "closed"].map(
                      (s) => (
                        <option key={s}>{s}</option>
                      ),
                    )}
                  </select>
                  <select
                    aria-label="Filter assignee"
                    value={assignee}
                    onChange={(e) => setAssignee(e.target.value)}
                  >
                    <option value="">All assignees</option>
                    <option value="unassigned">Unassigned</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.username}
                      </option>
                    ))}
                  </select>
                </div>
                {visible.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>CASE / AFFECTED IDENTITY</th>
                          <th>SEVERITY</th>
                          <th>STATUS</th>
                          <th>ASSIGNED TO</th>
                          <th>EVIDENCE</th>
                          <th>
                            <span className="sr-only">Open case</span>
                          </th>
                        </tr>
                      </thead>
                      <tbody>
                        {visible.map((c) => (
                          <tr key={c.id}>
                            <td>
                              <button
                                className="case-link"
                                onClick={() => void act(() => openCase(c.id))}
                              >
                                <span className="case-number">
                                  INC-{String(c.id).padStart(4, "0")}
                                </span>
                                <strong>{c.host}</strong>
                                <span>
                                  {c.username}{" "}
                                  {c.synthetic && <em>Synthetic</em>}
                                </span>
                              </button>
                            </td>
                            <td>
                              <Badge value={c.severity} />
                            </td>
                            <td>
                              <Badge value={c.status} />
                            </td>
                            <td>
                              {users.find((u) => u.id === c.assignee_id)
                                ?.username || (
                                <span className="muted">Unassigned</span>
                              )}
                            </td>
                            <td>
                              <strong>{c.finding_count}</strong> detections
                              <small>{c.evidence_count} evidence records</small>
                            </td>
                            <td>
                              <button
                                className="icon-button"
                                aria-label={`Open case ${c.id}`}
                                onClick={() => void act(() => openCase(c.id))}
                              >
                                <ArrowUpRight size={18} />
                              </button>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty
                    title={
                      cases.length
                        ? "No cases match these filters"
                        : "Your investigation queue is clear"
                    }
                    text={
                      cases.length
                        ? "Try a different host, severity, status or assignee."
                        : "Upload JSONL telemetry to begin. Benign logs may complete without creating a case."
                    }
                  />
                )}
                <footer className="panel-footer">
                  Showing {visible.length} of {cases.length} recent cases · Up
                  to 200 records
                </footer>
              </section>
              <div className="context-note">
                <FileText size={20} />
                <div>
                  <strong>A clear chain from evidence to report</strong>
                  <p>
                    Each detection links to source records. Review the context,
                    record your assessment, then export your investigation.
                  </p>
                </div>
              </div>
            </>
          )}
          {selected && page === "cases" && (
            <>
              <button className="back" onClick={() => setSelected(null)}>
                <ArrowLeft size={16} /> Back to investigations
              </button>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">
                    INC-{String(selected.id).padStart(4, "0")}{" "}
                    {selected.synthetic
                      ? " / SYNTHETIC EVIDENCE"
                      : " / USER-SUPPLIED EVIDENCE"}
                  </p>
                  <h1>{selected.host}</h1>
                  <p className="muted">
                    Identity: <strong>{selected.username || "Unknown"}</strong>{" "}
                    · {selected.evidence.length} evidence records ·{" "}
                    {selected.findings.length} rule matches
                  </p>
                </div>
                <div className="actions">
                  <a
                    className="button"
                    href={`/api/cases/${selected.id}/report?format=json`}
                  >
                    <FileText size={16} /> JSON
                  </a>
                  <a
                    className="primary button"
                    href={`/api/cases/${selected.id}/report?format=markdown`}
                  >
                    <FileText size={16} /> Export report
                  </a>
                </div>
              </div>
              <div className="case-controls panel">
                <label>
                  Severity
                  <select
                    aria-label="Case severity"
                    value={selected.severity}
                    disabled={busy}
                    onChange={(e) =>
                      void act(() => patch({ severity: e.target.value }))
                    }
                  >
                    {["critical", "high", "medium", "low"].map((s) => (
                      <option key={s}>{s}</option>
                    ))}
                  </select>
                </label>
                <label>
                  Status
                  <select
                    aria-label="Case status"
                    value={selected.status}
                    disabled={busy}
                    onChange={(e) =>
                      void act(() => patch({ status: e.target.value }))
                    }
                  >
                    {["open", "investigating", "resolved", "closed"].map(
                      (s) => (
                        <option
                          key={s}
                          disabled={
                            s !== selected.status &&
                            !(
                              {
                                open: ["investigating"],
                                investigating: ["open", "resolved"],
                                resolved:
                                  user.role === "administrator"
                                    ? ["investigating", "closed"]
                                    : ["investigating"],
                                closed:
                                  user.role === "administrator"
                                    ? ["investigating"]
                                    : [],
                              } as Record<string, string[]>
                            )[selected.status].includes(s)
                          }
                        >
                          {s}
                        </option>
                      ),
                    )}
                  </select>
                </label>
                <label>
                  Assigned analyst
                  <select
                    aria-label="Case assignee"
                    disabled={busy}
                    value={selected.assignee_id ?? ""}
                    onChange={(e) =>
                      void act(() =>
                        patch({
                          assignee_id: e.target.value
                            ? Number(e.target.value)
                            : null,
                        }),
                      )
                    }
                  >
                    <option value="">Unassigned</option>
                    {users.map((u) => (
                      <option key={u.id} value={u.id}>
                        {u.username}
                      </option>
                    ))}
                  </select>
                </label>
                <span className="muted small">
                  Every change is recorded.
                  <br />
                  Version {selected.version}
                </span>
              </div>
              <div className="investigation-grid">
                <section className="panel evidence-panel">
                  <div
                    className="tabs"
                    role="tablist"
                    aria-label="Investigation sections"
                  >
                    {[
                      ["evidence", "Evidence timeline"],
                      ["notes", "Analyst notes"],
                      ["history", "Audit trail"],
                      ["draft", "Report draft"],
                    ].map(([id, title]) => (
                      <button
                        role="tab"
                        aria-selected={tab === id}
                        key={id}
                        onClick={() => setTab(id)}
                      >
                        {title}
                      </button>
                    ))}
                  </div>
                  {tab === "evidence" && (
                    <div className="timeline">
                      <div className="section-intro">
                        <h2>Reconstruct the activity</h2>
                        <p className="muted small">
                          Chronological source records · timestamps displayed in
                          UTC
                        </p>
                      </div>
                      {selected.evidence.map((e) => (
                        <article
                          className="event"
                          id={e.evidence_id}
                          key={e.evidence_id}
                        >
                          <span className="timeline-dot" />
                          <div className="event-top">
                            <code>{e.evidence_id}</code>
                            <time>
                              {e.timestamp
                                .replace("T", " ")
                                .replace("+00:00", " UTC")}
                            </time>
                          </div>
                          <h3>
                            {(
                              {
                                "4625": "Failed authentication",
                                "4624": "Successful authentication",
                                "1": "Process created",
                                "4104": "PowerShell script block",
                                "3": "Outbound network connection",
                                "4663": "File access",
                                "11": "File created",
                                "4688": "Process created",
                              } as Record<string, string>
                            )[e.event_id] || "Security event"}{" "}
                            <span>Event {e.event_id}</span>
                          </h3>
                          {Boolean(
                            e.command_line || e.target_path || e.destination_ip,
                          ) && (
                            <pre>
                              {String(
                                e.command_line ||
                                  e.target_path ||
                                  `${e.destination_ip}:${e.destination_port}`,
                              )}
                            </pre>
                          )}
                          <details>
                            <summary>View source record</summary>
                            <pre>{JSON.stringify(e, null, 2)}</pre>
                          </details>
                        </article>
                      ))}
                    </div>
                  )}
                  {tab === "notes" && (
                    <div className="panel-body">
                      <h2>Analyst assessment</h2>
                      <p className="muted">
                        Separate observations from hypotheses. Reference
                        evidence IDs in your notes.
                      </p>
                      <form
                        onSubmit={(e) => {
                          e.preventDefault();
                          void act(async () => {
                            await api(`/cases/${selected.id}/comments`, {
                              method: "POST",
                              body: JSON.stringify({ text: comment }),
                            });
                            setComment("");
                            setSelected(
                              await api<Detail>("/cases/" + selected.id),
                            );
                            setNotice("Note added to the investigation.");
                          });
                        }}
                      >
                        <label>
                          Investigation note
                          <textarea
                            required
                            maxLength={5000}
                            value={comment}
                            onChange={(e) => setComment(e.target.value)}
                            placeholder="Observed… [U1-E0001]. Further validation needed…"
                          />
                        </label>
                        <button
                          className="primary"
                          disabled={busy || !comment.trim()}
                        >
                          Add note
                        </button>
                      </form>
                      <ActivityList
                        entries={selected.activities.filter(
                          (a) => a.kind === "comment",
                        )}
                      />
                    </div>
                  )}
                  {tab === "history" && (
                    <div className="panel-body">
                      <h2>Accountable by design</h2>
                      <p className="muted">
                        Who changed what, and when. Application users cannot
                        edit these entries.
                      </p>
                      <ActivityList entries={selected.activities} />
                    </div>
                  )}
                  {tab === "draft" && (
                    <div className="panel-body">
                      <h2>Evidence-linked report draft</h2>
                      <p className="muted">
                        Generate a local evidence summary, or use an optional
                        configured AI provider. Every draft requires your
                        review. No containment actions are executed.
                      </p>
                      <button
                        className="primary"
                        disabled={busy}
                        onClick={() =>
                          void act(async () =>
                            setDraft(
                              await api(`/cases/${selected.id}/draft`, {
                                method: "POST",
                              }),
                            ),
                          )
                        }
                      >
                        <FileText size={16} /> Prepare draft
                      </button>
                      {draft && (
                        <>
                          <div className="disclosure draft-warning">
                            <AlertTriangle size={17} /> Unreviewed draft ·{" "}
                            {draft.source}
                          </div>
                          <pre className="draft">{draft.text}</pre>
                          <button
                            disabled={busy}
                            onClick={() =>
                              void act(async () => {
                                await api(`/cases/${selected.id}/comments`, {
                                  method: "POST",
                                  body: JSON.stringify({
                                    text:
                                      "Analyst-reviewed draft:\n" + draft.text,
                                  }),
                                });
                                setSelected(
                                  await api<Detail>("/cases/" + selected.id),
                                );
                                setNotice(
                                  "Reviewed draft saved as an analyst note.",
                                );
                                setDraft(null);
                              })
                            }
                          >
                            I reviewed the evidence — save as a note
                          </button>
                        </>
                      )}
                    </div>
                  )}
                </section>
                <aside
                  className="detection-column"
                  aria-label="Detection context"
                >
                  <div className="panel panel-body">
                    <p className="eyebrow">DETECTION CONTEXT</p>
                    <h2>Why this case exists</h2>
                    <p className="muted small">
                      Heuristic matches from the SOC investigation lab. Validate
                      each finding against the source evidence.
                    </p>
                    {selected.findings.map((f, i) => (
                      <article className="finding" key={i}>
                        <div className="finding-top">
                          <code>{f.rule_id}</code>
                          <Badge value={f.severity} />
                        </div>
                        <h3>{f.title}</h3>
                        <p>{f.description}</p>
                        <div className="mitre">
                          {f.mitre_attack.join(" · ")}
                        </div>
                        <div className="evidence-links">
                          {f.evidence_ids.map((id) => (
                            <a
                              href={"#" + id}
                              key={id}
                              onClick={() => setTab("evidence")}
                            >
                              {id}
                            </a>
                          ))}
                        </div>
                      </article>
                    ))}
                  </div>
                  <div className="uncertainty">
                    <AlertTriangle size={18} />
                    <div>
                      <strong>What remains unknown</strong>
                      <p>
                        Intent, authorization, archive contents and data loss
                        need independent validation.
                      </p>
                    </div>
                  </div>
                </aside>
              </div>
            </>
          )}
          {page === "uploads" && (
            <>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">INGEST & CORRELATE</p>
                  <h1>Log uploads</h1>
                  <p className="muted">
                    Validate telemetry, track processing, and follow new
                    investigations.
                  </p>
                </div>
              </div>
              <div className="upload-grid">
                <form
                  className="panel upload-form"
                  onSubmit={(e) => {
                    e.preventDefault();
                    void act(async () => {
                      if (!file) throw new Error("Choose a JSONL file.");
                      if (file.size > 5 * 1024 * 1024)
                        throw new Error("Upload exceeds the 5 MiB limit.");
                      await api("/uploads", {
                        method: "POST",
                        headers: {
                          "Content-Type": "application/x-ndjson",
                          "X-Filename": file.name,
                          "X-Synthetic": String(synthetic),
                        },
                        body: file,
                      });
                      setNotice(
                        "Upload queued. The worker will correlate your evidence shortly.",
                      );
                      setFile(null);
                      await refresh();
                    });
                  }}
                >
                  <UploadCloud size={32} />
                  <h2>Add security telemetry</h2>
                  <p>UTF-8 JSONL · Up to 5 MiB and 10,000 records</p>
                  <label className="file-label">
                    Choose a JSONL file
                    <input
                      type="file"
                      accept=".jsonl,.ndjson"
                      onChange={(e) => setFile(e.target.files?.[0] || null)}
                    />
                  </label>
                  {file && <span className="small">Selected: {file.name}</span>}
                  <label className="checkbox">
                    <input
                      type="checkbox"
                      checked={synthetic}
                      onChange={(e) => setSynthetic(e.target.checked)}
                    />{" "}
                    This upload contains synthetic demo data
                  </label>
                  <button className="primary" disabled={busy || !file}>
                    Validate & queue <ArrowUpRight size={16} />
                  </button>
                </form>
                <div className="panel panel-body">
                  <p className="eyebrow">BEFORE YOU UPLOAD</p>
                  <h2>Keep the evidence useful.</h2>
                  <ol className="steps">
                    <li>
                      <strong>One event per line</strong>
                      <p>
                        Require timestamp with timezone, event_id, host and
                        channel. Unknown fields are rejected.
                      </p>
                    </li>
                    <li>
                      <strong>Same data, one job</strong>
                      <p>
                        Canonical event hashes prevent duplicate jobs, even when
                        lines or JSON keys are reordered.
                      </p>
                    </li>
                    <li>
                      <strong>Know what is retained</strong>
                      <p>
                        Input stays in PostgreSQL until an administrator deletes
                        it. Deleting input preserves case evidence, audit
                        history and the duplicate hash.
                      </p>
                    </li>
                  </ol>
                </div>
              </div>
              <section className="panel">
                <div className="panel-title">
                  <h2>Processing history</h2>
                  <button
                    className="text-button"
                    onClick={() => void act(refresh)}
                  >
                    <RefreshCw size={14} /> Refresh
                  </button>
                </div>
                {uploads.length ? (
                  <div className="table-wrap">
                    <table>
                      <thead>
                        <tr>
                          <th>UPLOAD</th>
                          <th>STATE</th>
                          <th>RECORDS</th>
                          <th>RETAINED INPUT</th>
                          <th>ACTIONS</th>
                        </tr>
                      </thead>
                      <tbody>
                        {uploads.map((u) => (
                          <tr key={u.id}>
                            <td>
                              <strong>
                                #{u.id} · {u.filename}
                              </strong>
                              <small>
                                {u.synthetic
                                  ? "Synthetic data"
                                  : "User-supplied data"}{" "}
                                · {u.attempts} processing attempts
                              </small>
                              {u.error && (
                                <p className="inline-error">{u.error}</p>
                              )}
                            </td>
                            <td>
                              <Badge value={u.status} />
                            </td>
                            <td>{u.event_count}</td>
                            <td>
                              {u.payload_retained ? "Retained" : "Deleted"}
                            </td>
                            <td>
                              {user.role === "administrator" && (
                                <div className="actions">
                                  {u.status === "failed" &&
                                    u.payload_retained && (
                                      <button
                                        disabled={busy}
                                        onClick={() =>
                                          void act(async () => {
                                            await api(
                                              `/uploads/${u.id}/retry`,
                                              { method: "POST" },
                                            );
                                            await refresh();
                                          })
                                        }
                                      >
                                        Retry
                                      </button>
                                    )}
                                  {!["queued", "processing"].includes(
                                    u.status,
                                  ) &&
                                    u.payload_retained && (
                                      <button
                                        disabled={busy}
                                        onClick={() => {
                                          if (
                                            confirm(
                                              "Delete retained upload input? Case evidence and audit history will remain. This input cannot be restored.",
                                            )
                                          )
                                            void act(async () => {
                                              await api(
                                                `/uploads/${u.id}/payload`,
                                                { method: "DELETE" },
                                              );
                                              await refresh();
                                            });
                                        }}
                                      >
                                        Delete input
                                      </button>
                                    )}
                                </div>
                              )}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : (
                  <Empty
                    title="No uploads yet"
                    text="Choose synthetic-events.jsonl from the repository's data folder to explore the workflow."
                  />
                )}
              </section>
            </>
          )}
          {page === "users" && (
            <>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">ADMINISTRATION</p>
                  <h1>Accounts</h1>
                  <p className="muted">
                    One trusted workspace. Permissions enforced by the API.
                  </p>
                </div>
              </div>
              <div className="upload-grid">
                <section className="panel panel-body">
                  <h2>Workspace members</h2>
                  {users.map((u) => (
                    <div className="member" key={u.id}>
                      <span className="avatar">
                        {u.username.slice(0, 2).toUpperCase()}
                      </span>
                      <strong>{u.username}</strong>
                      <Badge value={u.role} />
                    </div>
                  ))}
                </section>
                <form
                  className="panel panel-body"
                  onSubmit={(e) => {
                    e.preventDefault();
                    const form = e.currentTarget;
                    const body = Object.fromEntries(new FormData(form));
                    void act(async () => {
                      await api("/users", {
                        method: "POST",
                        body: JSON.stringify(body),
                      });
                      form.reset();
                      await refresh();
                      setNotice("Account created.");
                    });
                  }}
                >
                  <h2>Create account</h2>
                  <label>
                    Username
                    <input
                      name="username"
                      pattern="[a-zA-Z0-9_.-]+"
                      maxLength={80}
                      required
                      autoComplete="off"
                    />
                  </label>
                  <label>
                    Password
                    <input
                      name="password"
                      type="password"
                      minLength={12}
                      maxLength={256}
                      required
                      autoComplete="new-password"
                    />
                  </label>
                  <label>
                    Role
                    <select name="role">
                      <option value="analyst">Analyst</option>
                      <option value="administrator">Administrator</option>
                    </select>
                  </label>
                  <p className="muted small">
                    Use at least 12 characters. Administrators can manage
                    accounts, close cases, retry jobs and delete retained input.
                  </p>
                  <button className="primary" disabled={busy}>
                    Create account
                  </button>
                </form>
              </div>
            </>
          )}
          {page === "audit" && (
            <>
              <div className="page-heading">
                <div>
                  <p className="eyebrow">ADMINISTRATION</p>
                  <h1>Audit log</h1>
                  <p className="muted">
                    Latest 200 workspace events, including authentication and
                    data lifecycle actions.
                  </p>
                </div>
              </div>
              <section className="panel panel-body">
                <ActivityList entries={audit} />
              </section>
            </>
          )}
          <footer className="workspace-footer">
            IncidentDesk <span>Independent portfolio project · jblaz6335</span>
          </footer>
        </main>
      </div>
    </div>
  );
}
function Empty({ title, text }: { title: string; text: string }) {
  return (
    <div className="empty">
      <Search size={28} />
      <h3>{title}</h3>
      <p>{text}</p>
    </div>
  );
}
function ActivityList({ entries }: { entries: Entry[] }) {
  return (
    <div className="activity-list">
      {entries.length ? (
        entries.map((a) => (
          <article key={a.id}>
            <div>
              <strong>{a.actor}</strong>
              <span>{label(a.kind)}</span>
              <time>{date(a.created)}</time>
            </div>
            <p>{a.detail}</p>
          </article>
        ))
      ) : (
        <Empty
          title="Nothing recorded yet"
          text="Your investigation notes and decisions will appear here."
        />
      )}
    </div>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
