# Detection lineage and data disclosure

I built IncidentDesk on my [SOC Incident Investigation Lab](https://github.com/jblaz6335/soc-incident-investigation-lab), pinned to commit [`c53542720f2aae6e555647d97911416dd35f5053`](https://github.com/jblaz6335/soc-incident-investigation-lab/tree/c53542720f2aae6e555647d97911416dd35f5053).

I reused `src/soc_lab/models.py` and `src/soc_lab/detections.py` unchanged in `backend/app/vendor/`. The original MIT copyright notice, Copyright (c) 2026 Joshua Hernandez, is preserved in `backend/app/vendor/LICENSE`. I copied `data/sample_events.jsonl` to `data/synthetic-events.jsonl`. The root license also preserves the original copyright notice.

All bundled telemetry is synthetic. Names, hosts, hashes, addresses and paths were created for the lab. The external IP addresses use RFC 5737 documentation ranges and do not represent real infrastructure. No malware is included or executed. The original scenario's private IP addresses are simulated internal endpoints. Browser-test fixtures derive from the same synthetic data and use generated hostnames.

My adapter adds per-upload evidence IDs, groups events by host and case-insensitive username within fixed 30-minute windows, and links findings to matching records. It deliberately softens the original chain-oriented descriptions for network, file-access and archive rules: a rule match alone cannot establish prior compromise or exfiltration. Original recommendations remain data inside the vendored finding structure; IncidentDesk never executes them.

| Rule | What I retained | What it cannot establish |
| --- | --- | --- |
| SOC-AUTH-001 | At least five failed logons followed by success for the same host, identity and source within ten minutes | Credential theft or unauthorized use |
| SOC-EXEC-001 | PowerShell command indicators such as encoded commands and download patterns | Malicious intent; administrators can use these patterns |
| SOC-NET-001 | PowerShell connections outside the rule's private-network ranges | Command-and-control or exfiltration |
| SOC-DATA-001 | Sensitive filename markers in Event 4663 | File contents or whether access was authorized |
| SOC-DATA-002 | Sensitive filename markers in archive-creation events | Archive contents or transmission |

The original network classifier is a lab heuristic, not a full public-routing classifier. Documentation-range addresses intentionally trigger the demonstration. I do not claim enterprise detection coverage or measured false-positive rates.
