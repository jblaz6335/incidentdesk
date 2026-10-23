"""Adapter around the MIT-licensed SOC lab rules; see docs/attribution.md."""

from collections import defaultdict
from datetime import timedelta
from .vendor.models import SecurityEvent
from .vendor.detections import run_detections, _is_external


def correlate(payload, upload_id):
    groups = defaultdict(list)
    for index, raw in enumerate(payload, 1):
        event = SecurityEvent.from_mapping(raw)
        groups[(event.host, event.username.lower())].append(
            (event, dict(raw, evidence_id=f"U{upload_id}-E{index:04d}"))
        )
    results = []
    for (host, username), rows in groups.items():
        rows.sort(key=lambda row: row[0].timestamp)
        windows = []
        for row in rows:
            if not windows or row[0].timestamp - windows[-1][0][
                0
            ].timestamp > timedelta(minutes=30):
                windows.append([])
            windows[-1].append(row)
        for window in windows:
            findings = []
            for finding in run_detections([r[0] for r in window]):
                data = finding.to_dict()
                ids = {
                    "SOC-AUTH-001": {"4625", "4624"},
                    "SOC-EXEC-001": {"1", "4104"},
                    "SOC-NET-001": {"3"},
                    "SOC-DATA-001": {"4663"},
                    "SOC-DATA-002": {"11"},
                }[finding.rule_id]
                candidates = [
                    r
                    for r in window
                    if r[0].event_id in ids
                    and finding.first_seen <= r[0].timestamp <= finding.last_seen
                ]
                if finding.rule_id == "SOC-AUTH-001":
                    # The original finding includes its source IP; don't cite unrelated failures.
                    candidates = [
                        r
                        for r in candidates
                        if f"Source: {r[0].source_ip}; host: {host}; user: {r[0].username}"
                        in finding.evidence
                        and (
                            (
                                r[0].event_id == "4625"
                                and r[0].outcome.lower() == "failure"
                            )
                            or (
                                r[0].event_id == "4624"
                                and r[0].outcome.lower() == "success"
                                and r[0].timestamp == finding.last_seen
                            )
                        )
                    ]
                elif finding.rule_id == "SOC-EXEC-001":
                    candidates = [
                        r
                        for r in candidates
                        if "powershell"
                        in (r[0].image + " " + r[0].command_line).lower()
                        and any(
                            term in (r[0].image + " " + r[0].command_line).lower()
                            for term in (
                                "-encodedcommand",
                                "frombase64string",
                                "downloadstring",
                                "invoke-expression",
                                "iex(",
                            )
                        )
                    ]
                elif finding.rule_id == "SOC-NET-001":
                    candidates = [
                        r
                        for r in candidates
                        if "powershell" in r[0].image.lower()
                        and _is_external(r[0].destination_ip)
                        and f"Destination: {r[0].destination_ip}:{r[0].destination_port}"
                        in finding.evidence
                    ]
                else:
                    candidates = [
                        r
                        for r in candidates
                        if any(
                            marker in r[0].target_path.lower()
                            for marker in (
                                "confidential",
                                "restricted",
                                "client_list",
                                "credentials",
                            )
                        )
                        and (
                            finding.rule_id != "SOC-DATA-002"
                            or r[0]
                            .target_path.lower()
                            .endswith((".zip", ".7z", ".rar"))
                        )
                    ]
                data["evidence_ids"] = [r[1]["evidence_id"] for r in candidates]
                # Original rules suggest a chain that individual matches alone cannot prove.
                data["description"] = {
                    "SOC-NET-001": "PowerShell connected outside the configured private ranges. This alone does not establish command-and-control.",
                    "SOC-DATA-001": "A sensitive filename marker matched an access event. Authorization and data loss are unconfirmed.",
                    "SOC-DATA-002": "An archive filename matched a sensitive marker. Archive contents and exfiltration are unconfirmed.",
                }.get(finding.rule_id, data["description"])
                data["title"] = {
                    "SOC-DATA-001": "Sensitive filename access",
                    "SOC-DATA-002": "Potential sensitive archive staging",
                }.get(finding.rule_id, data["title"])
                findings.append(data)
            if findings:
                results.append(
                    dict(
                        host=host,
                        username=username,
                        title=f"{host} · {username or 'unknown identity'}",
                        severity="critical"
                        if any(f["severity"] == "critical" for f in findings)
                        else "high",
                        evidence=[r[1] for r in window],
                        findings=findings,
                    )
                )
    return results
