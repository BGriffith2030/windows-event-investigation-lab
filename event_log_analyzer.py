#!/usr/bin/env python3
"""
Windows Security Event Log Analyzer
-----------------------------------
Reads a CSV export of Windows Security events and hunts for the patterns a
SOC analyst looks for first:

  * Brute force password guessing   (many Event ID 4625 failures)
  * A success right after failures   (4625 burst followed by a 4624)
  * Special privileges assigned      (Event ID 4672)
  * A new service installed          (Event ID 7045, a common persistence trick)
  * A new user account created       (Event ID 4720)

Usage:
    python event_log_analyzer.py sample_events.csv
    python event_log_analyzer.py events.csv --threshold 10 --out report.txt

The CSV must have these columns:
    timestamp, event_id, logon_type, account, source_ip, workstation

Only the Python standard library is used, so it runs anywhere Python 3 does.
"""

import argparse
import csv
import sys
from collections import Counter, defaultdict

# Event IDs this tool understands. Keeping them in one place makes the code
# easy to extend and easy to explain.
FAILED_LOGON = 4625
SUCCESSFUL_LOGON = 4624
SPECIAL_PRIVILEGES = 4672
SERVICE_INSTALLED = 7045
ACCOUNT_CREATED = 4720


def load_events(path):
    """Read the CSV export and return a list of event dictionaries."""
    events = []
    with open(path, newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            row["event_id"] = int(row["event_id"])
            events.append(row)
    # Chronological order matters: a success only counts as suspicious if it
    # comes AFTER the failures, so sort by time before analyzing.
    events.sort(key=lambda e: e["timestamp"])
    return events


def find_brute_force(events, threshold):
    """Group failed logons by account and source IP. Any group that reaches
    the threshold looks like password guessing, not a typo."""
    groups = defaultdict(list)
    for event in events:
        if event["event_id"] == FAILED_LOGON:
            groups[(event["account"], event["source_ip"])].append(event)
    return {key: hits for key, hits in groups.items() if len(hits) >= threshold}


def find_success_after_failures(events, brute_force_groups):
    """A successful logon for a brute-forced account, from the same source IP,
    after the failures started, is the moment an investigation escalates."""
    alerts = []
    for (account, source_ip), failures in brute_force_groups.items():
        first_failure = failures[0]["timestamp"]
        for event in events:
            if (
                event["event_id"] == SUCCESSFUL_LOGON
                and event["account"] == account
                and event["source_ip"] == source_ip
                and event["timestamp"] > first_failure
            ):
                alerts.append(event)
    return alerts


def pick(events, event_id):
    """Return every event with the given ID, in time order."""
    return [e for e in events if e["event_id"] == event_id]


def build_report(events, threshold):
    """Run every check and return the report as a single string."""
    lines = []
    lines.append("=" * 64)
    lines.append("WINDOWS SECURITY EVENT LOG ANALYSIS")
    lines.append("=" * 64)
    lines.append(f"Total events reviewed : {len(events)}")
    counts = Counter(e["event_id"] for e in events)
    lines.append(f"Failed logons (4625)  : {counts[FAILED_LOGON]}")
    lines.append(f"Successful logons     : {counts[SUCCESSFUL_LOGON]}")
    lines.append("")

    lines.append("-" * 64)
    lines.append(f"1. POSSIBLE BRUTE FORCE (threshold: {threshold} failures)")
    lines.append("-" * 64)
    brute_force = find_brute_force(events, threshold)
    if brute_force:
        for (account, source_ip), hits in sorted(brute_force.items()):
            lines.append(
                f"  [!] Account '{account}' from {source_ip}: "
                f"{len(hits)} failed logons between "
                f"{hits[0]['timestamp']} and {hits[-1]['timestamp']}"
            )
    else:
        lines.append("  None found.")
    lines.append("")

    lines.append("-" * 64)
    lines.append("2. SUCCESSFUL LOGON AFTER A FAILURE BURST (possible breach)")
    lines.append("-" * 64)
    breaches = find_success_after_failures(events, brute_force)
    if breaches:
        for event in breaches:
            lines.append(
                f"  [!!] '{event['account']}' logged on successfully from "
                f"{event['source_ip']} at {event['timestamp']} "
                f"(workstation {event['workstation']})"
            )
    else:
        lines.append("  None found.")
    lines.append("")

    lines.append("-" * 64)
    lines.append("3. SPECIAL PRIVILEGES ASSIGNED AT LOGON (4672)")
    lines.append("-" * 64)
    privileged = pick(events, SPECIAL_PRIVILEGES)
    if privileged:
        for event in privileged:
            lines.append(
                f"  [*] {event['timestamp']}  account '{event['account']}' "
                f"from {event['source_ip']}"
            )
    else:
        lines.append("  None found.")
    lines.append("")

    lines.append("-" * 64)
    lines.append("4. NEW SERVICE INSTALLED (7045, possible persistence)")
    lines.append("-" * 64)
    services = pick(events, SERVICE_INSTALLED)
    if services:
        for event in services:
            lines.append(
                f"  [!] {event['timestamp']}  on {event['workstation']} "
                f"(recorded by '{event['account']}')"
            )
    else:
        lines.append("  None found.")
    lines.append("")

    lines.append("-" * 64)
    lines.append("5. NEW USER ACCOUNT CREATED (4720)")
    lines.append("-" * 64)
    created = pick(events, ACCOUNT_CREATED)
    if created:
        for event in created:
            lines.append(
                f"  [!] {event['timestamp']}  new account activity on "
                f"{event['workstation']} (recorded by '{event['account']}')"
            )
    else:
        lines.append("  None found.")
    lines.append("")
    lines.append("End of report.")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(
        description="Hunt for suspicious patterns in a Windows Security event log export."
    )
    parser.add_argument("csv_file", help="Path to the event log CSV export")
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Failed logons from one source that count as brute force (default: 5)",
    )
    parser.add_argument(
        "--out",
        help="Optional file path to also save the report as text",
    )
    args = parser.parse_args()

    try:
        events = load_events(args.csv_file)
    except FileNotFoundError:
        sys.exit(f"File not found: {args.csv_file}")
    except (KeyError, ValueError) as error:
        sys.exit(f"Could not parse {args.csv_file}: {error}")

    report = build_report(events, args.threshold)
    print(report)

    if args.out:
        with open(args.out, "w", encoding="utf-8") as handle:
            handle.write(report + "\n")
        print(f"\nReport saved to {args.out}")


if __name__ == "__main__":
    main()
