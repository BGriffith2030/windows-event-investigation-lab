# Windows Event Investigation Lab

A security operations lab built around a real SOC task: taking a Windows Security event log export and working it like an investigation. The lab includes a Python analyzer that hunts the patterns an analyst checks first, a sample log that tells a complete attack story, and the written investigation that follows from it.

## Scenario

A finance workstation, WS-FINANCE-03, generated a day of Security events. Buried in the normal logon traffic is an external brute force attack that succeeds, followed by privilege use, a new service installed for persistence, and a new account created. The analyst's job: find it, prove the timeline, and write it up.

The sample data uses the documentation IP range 203.0.113.0/24 (RFC 5737) for the external address and a VirtualBox host-only range (192.168.56.0/24) for the lab network, so nothing in this repository points at a real system.

## What is in this repository

| File | Purpose |
| --- | --- |
| `event_log_analyzer.py` | The analyzer. Reads a CSV event export and reports five checks, in plain language. |
| `sample_events.csv` | A one day Security log export (33 events) containing the full attack story plus normal background traffic. |
| `investigation-report.md` | The written investigation: summary, timeline, findings, and recommendations. |
| `LICENSE` | MIT license. |

## The five checks

| Check | Event ID | Why it matters |
| --- | --- | --- |
| Brute force detection | 4625 | Repeated failed logons from one source against one account means password guessing, not a typo. |
| Success after failures | 4624 after 4625 | A successful logon right after a failure burst, from the same source, is the moment a guess worked. |
| Special privileges assigned | 4672 | Shows when an account with administrative rights logs on, and from where. |
| New service installed | 7045 | Services are a common persistence method; an unexpected one after a breach is a red flag. |
| New account created | 4720 | Attackers create accounts to keep access. Any creation outside a change process needs an owner. |

## How to run it

Python 3, standard library only. Nothing to install.

```bash
python event_log_analyzer.py sample_events.csv
```

Options:

```bash
python event_log_analyzer.py events.csv --threshold 10 --out report.txt
```

- `--threshold` sets how many failed logons from one source count as brute force (default 5).
- `--out` also saves the report as a text file.

The input CSV needs these columns: `timestamp, event_id, logon_type, account, source_ip, workstation`. That is the shape a filtered Event Viewer export produces after light cleanup, and the shape a SIEM export can be mapped to.

## What the analyzer finds in the sample data

- 6 failed logons against `administrator` and 7 against `j.miller`, all from 203.0.113.45 inside one minute: brute force.
- A successful `j.miller` logon from that same address at 13:24:05, followed one second later by special privileges (4672): the guess worked, and the account is privileged.
- A new service installed at 13:31 and a new account created at 13:36, both tied to the same session: persistence.
- Normal traffic (an administrator's morning logon, a mistyped password at 08:14, ordinary user logons) is reported in context and correctly not escalated.

The full write-up is in [investigation-report.md](investigation-report.md).

## Skills demonstrated

- Windows Security auditing: logon events, privilege use, service installation, account management
- Log analysis and event correlation across a timeline
- Python for security operations: CSV parsing, grouping, threshold detection, report generation (standard library only)
- Incident documentation: turning raw events into findings and recommendations a manager can act on
- Lab safety: documentation and private address ranges only, no real targets

## How this maps to the job

This is the daily rhythm of Tier 1 SOC work: pull the events, separate the attack from the noise, prove the sequence with timestamps, and hand off a clear report. The same five checks are what most SIEM detection rules for Windows authentication are built from.
