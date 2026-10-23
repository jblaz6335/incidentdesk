from __future__ import annotations

import ipaddress
from collections import defaultdict
from datetime import timedelta

from .models import Finding, SecurityEvent


def detect_brute_force_success(
    events: list[SecurityEvent], threshold: int = 5, window_minutes: int = 10
) -> list[Finding]:
    failures: dict[tuple[str, str, str], list[SecurityEvent]] = defaultdict(list)
    findings: list[Finding] = []
    window = timedelta(minutes=window_minutes)

    for event in sorted(events, key=lambda item: item.timestamp):
        key = (event.host, event.username.lower(), event.source_ip)
        if event.event_id == "4625" and event.outcome.lower() == "failure":
            failures[key].append(event)
            continue
        if event.event_id != "4624" or event.outcome.lower() != "success":
            continue

        recent = [
            failed
            for failed in failures.get(key, [])
            if timedelta(0) <= event.timestamp - failed.timestamp <= window
        ]
        if len(recent) < threshold:
            continue

        findings.append(
            Finding(
                rule_id="SOC-AUTH-001",
                title="Brute force followed by successful authentication",
                severity="critical",
                description=(
                    f"{len(recent)} failed logons for {event.username} from "
                    f"{event.source_ip} were followed by a successful logon."
                ),
                first_seen=recent[0].timestamp,
                last_seen=event.timestamp,
                evidence=(
                    f"Event 4625 count: {len(recent)}",
                    f"Successful Event 4624 at {event.timestamp.isoformat()}",
                    f"Source: {event.source_ip}; host: {event.host}; user: {event.username}",
                ),
                mitre_attack=("T1110 - Brute Force", "T1078 - Valid Accounts"),
                recommended_actions=(
                    "Disable or contain the affected account.",
                    "Revoke active sessions and reset credentials.",
                    "Block the source and investigate adjacent authentication activity.",
                ),
            )
        )
    return findings


def detect_suspicious_powershell(events: list[SecurityEvent]) -> list[Finding]:
    suspicious_terms = (
        "-encodedcommand",
        "frombase64string",
        "downloadstring",
        "invoke-expression",
        "iex(",
    )
    matches_by_identity: dict[
        tuple[str, str], list[tuple[SecurityEvent, tuple[str, ...]]]
    ] = defaultdict(list)
    for event in events:
        process_text = f"{event.image} {event.command_line}".lower()
        if event.event_id not in {"1", "4104"} or "powershell" not in process_text:
            continue
        matches = tuple(term for term in suspicious_terms if term in process_text)
        if not matches:
            continue
        matches_by_identity[(event.host, event.username.lower())].append((event, matches))

    findings: list[Finding] = []
    for (host, _username), matched_events in matches_by_identity.items():
        ordered = sorted(matched_events, key=lambda item: item[0].timestamp)
        indicators = sorted({indicator for _event, values in ordered for indicator in values})
        findings.append(
            Finding(
                rule_id="SOC-EXEC-001",
                title="Suspicious PowerShell execution",
                severity="high",
                description="PowerShell used encoded or download-oriented execution patterns.",
                first_seen=ordered[0][0].timestamp,
                last_seen=ordered[-1][0].timestamp,
                evidence=(
                    f"Events {', '.join(item[0].event_id for item in ordered)} on {host}",
                    f"Matched indicators: {', '.join(indicators)}",
                    *tuple(f"Command line: {item[0].command_line}" for item in ordered),
                ),
                mitre_attack=(
                    "T1059.001 - PowerShell",
                    "T1105 - Ingress Tool Transfer",
                ),
                recommended_actions=(
                    "Isolate the endpoint and preserve process telemetry.",
                    "Collect the PowerShell script-block and parent-process evidence.",
                    "Hunt for the command indicators across the environment.",
                ),
            )
        )
    return findings


def _is_external(address: str) -> bool:
    try:
        parsed = ipaddress.ip_address(address)
    except ValueError:
        return False
    internal_networks = (
        ipaddress.ip_network("10.0.0.0/8"),
        ipaddress.ip_network("172.16.0.0/12"),
        ipaddress.ip_network("192.168.0.0/16"),
        ipaddress.ip_network("fc00::/7"),
    )
    return not (
        parsed.is_loopback
        or parsed.is_link_local
        or any(parsed.version == network.version and parsed in network for network in internal_networks)
    )


def detect_suspicious_outbound(events: list[SecurityEvent]) -> list[Finding]:
    findings: list[Finding] = []
    for event in events:
        if event.event_id != "3" or "powershell" not in event.image.lower():
            continue
        if not _is_external(event.destination_ip):
            continue
        findings.append(
            Finding(
                rule_id="SOC-NET-001",
                title="PowerShell established an external network connection",
                severity="high",
                description="PowerShell connected to an external address after suspicious execution.",
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                evidence=(
                    f"Sysmon Event 3 on {event.host}",
                    f"Destination: {event.destination_ip}:{event.destination_port}",
                    f"Process: {event.image}",
                ),
                mitre_attack=("T1071.001 - Web Protocols",),
                recommended_actions=(
                    "Block and enrich the destination indicator.",
                    "Review proxy, DNS, and firewall telemetry for related activity.",
                ),
            )
        )
    return findings


def detect_sensitive_file_access(events: list[SecurityEvent]) -> list[Finding]:
    sensitive_markers = ("confidential", "restricted", "client_list", "credentials")
    findings: list[Finding] = []
    for event in events:
        if event.event_id != "4663":
            continue
        if not any(marker in event.target_path.lower() for marker in sensitive_markers):
            continue
        findings.append(
            Finding(
                rule_id="SOC-DATA-001",
                title="Sensitive file accessed after suspected compromise",
                severity="high",
                description="The affected identity accessed a sensitive file during the incident window.",
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                evidence=(
                    f"Event 4663 on {event.host}",
                    f"User: {event.username}",
                    f"Target: {event.target_path}; action: {event.action}",
                ),
                mitre_attack=("T1005 - Data from Local System",),
                recommended_actions=(
                    "Determine whether the file was staged, copied, or exfiltrated.",
                    "Notify the data owner and preserve file-access evidence.",
                ),
            )
        )
    return findings


def detect_sensitive_archive_staging(events: list[SecurityEvent]) -> list[Finding]:
    sensitive_markers = ("confidential", "restricted", "client_list", "credentials")
    archive_extensions = (".zip", ".7z", ".rar")
    findings: list[Finding] = []
    for event in events:
        target = event.target_path.lower()
        if event.event_id != "11" or not target.endswith(archive_extensions):
            continue
        if not any(marker in target for marker in sensitive_markers):
            continue
        findings.append(
            Finding(
                rule_id="SOC-DATA-002",
                title="Sensitive data staged in an archive",
                severity="high",
                description="A process created an archive whose name matches sensitive business data.",
                first_seen=event.timestamp,
                last_seen=event.timestamp,
                evidence=(
                    f"Sysmon Event 11 on {event.host}",
                    f"Process: {event.image}",
                    f"Archive: {event.target_path}",
                ),
                mitre_attack=("T1560.001 - Archive via Utility",),
                recommended_actions=(
                    "Preserve and hash the archive before containment cleanup.",
                    "Determine whether the archive was transmitted or copied elsewhere.",
                    "Hunt for similarly named archives across endpoints and shared storage.",
                ),
            )
        )
    return findings


def run_detections(events: list[SecurityEvent]) -> list[Finding]:
    findings = [
        *detect_brute_force_success(events),
        *detect_suspicious_powershell(events),
        *detect_suspicious_outbound(events),
        *detect_sensitive_file_access(events),
        *detect_sensitive_archive_staging(events),
    ]
    rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
    return sorted(findings, key=lambda item: (rank[item.severity], item.first_seen))
