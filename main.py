#!/usr/bin/env python3
"""TRJ-SOC-Toolkit: read-only Linux SSH authentication log analyzer."""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable


# Matches common OpenSSH messages, including "invalid user" variants.
FAILED_PASSWORD_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) "
    r"from (?P<ip>[0-9a-fA-F:.]+) port \d+"
)
INVALID_USER_RE = re.compile(
    r"Invalid user (?P<user>\S+) from (?P<ip>[0-9a-fA-F:.]+)"
)
AUTH_FAILURE_RE = re.compile(
    r"authentication failure;.*?rhost=(?P<ip>[0-9a-fA-F:.]+).*?"
    r"(?:user=(?P<user>\S+))?"
)


@dataclass(frozen=True)
class FailedAttempt:
    timestamp: str
    source_ip: str
    username: str
    message: str


@dataclass
class IPFinding:
    source_ip: str
    attempts: int
    usernames: list[str]
    first_seen: str
    last_seen: str
    possible_brute_force: bool


def parse_line(line: str) -> FailedAttempt | None:
    """Parse one common Linux SSH authentication log line."""
    match = FAILED_PASSWORD_RE.search(line)
    if not match:
        match = INVALID_USER_RE.search(line)
    if not match:
        match = AUTH_FAILURE_RE.search(line)
    if not match:
        return None

    timestamp = line[:15].strip() or "unknown"
    username = (match.groupdict().get("user") or "unknown").strip()
    source_ip = match.group("ip").strip()

    return FailedAttempt(
        timestamp=timestamp,
        source_ip=source_ip,
        username=username,
        message=line.strip(),
    )


def analyze_lines(lines: Iterable[str], threshold: int = 5) -> tuple[list[FailedAttempt], list[IPFinding]]:
    """Analyze log lines and group failed attempts by source IP."""
    if threshold < 1:
        raise ValueError("threshold must be at least 1")

    attempts: list[FailedAttempt] = []
    grouped: dict[str, list[FailedAttempt]] = defaultdict(list)

    for line in lines:
        event = parse_line(line)
        if event is not None:
            attempts.append(event)
            grouped[event.source_ip].append(event)

    findings: list[IPFinding] = []
    for source_ip, events in sorted(grouped.items()):
        findings.append(
            IPFinding(
                source_ip=source_ip,
                attempts=len(events),
                usernames=sorted({event.username for event in events}),
                first_seen=events[0].timestamp,
                last_seen=events[-1].timestamp,
                possible_brute_force=len(events) >= threshold,
            )
        )

    findings.sort(key=lambda item: (-item.attempts, item.source_ip))
    return attempts, findings


def write_json(path: Path, attempts: list[FailedAttempt], findings: list[IPFinding]) -> None:
    payload = {
        "tool": "TRJ-SOC-Toolkit",
        "event_type": "ssh_failed_authentication",
        "total_failed_attempts": len(attempts),
        "findings": [asdict(item) for item in findings],
    }
    path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def write_csv(path: Path, findings: list[IPFinding]) -> None:
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=[
                "source_ip", "attempts", "usernames",
                "first_seen", "last_seen", "possible_brute_force",
            ],
        )
        writer.writeheader()
        for finding in findings:
            row = asdict(finding)
            row["usernames"] = ", ".join(finding.usernames)
            writer.writerow(row)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyze Linux SSH authentication logs for repeated failed logins."
    )
    parser.add_argument("--log", required=True, type=Path, help="Path to auth.log or secure log")
    parser.add_argument(
        "--threshold", type=int, default=5,
        help="Failed attempts from one IP required to raise an alert (default: 5)",
    )
    parser.add_argument("--json", dest="json_path", type=Path, help="Optional JSON report path")
    parser.add_argument("--csv", dest="csv_path", type=Path, help="Optional CSV report path")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.threshold < 1:
        parser.error("--threshold must be at least 1")
    if not args.log.is_file():
        print(f"[ERROR] Log dosyası bulunamadı: {args.log}", file=sys.stderr)
        return 2

    try:
        with args.log.open("r", encoding="utf-8", errors="replace") as handle:
            attempts, findings = analyze_lines(handle, args.threshold)
    except OSError as exc:
        print(f"[ERROR] Log dosyası okunamadı: {exc}", file=sys.stderr)
        return 2

    print("\n=== TRJ SOC TOOLKIT | SSH LOG ANALYZER ===")
    if not attempts:
        print("[INFO] Desteklenen biçimde başarısız SSH kimlik doğrulama kaydı bulunamadı.")

    for finding in findings:
        if finding.possible_brute_force:
            print(
                f"[ALERT] Olası brute-force: {finding.source_ip} | "
                f"{finding.attempts} başarısız deneme | "
                f"kullanıcılar: {', '.join(finding.usernames)}"
            )
        else:
            print(
                f"[INFO] {finding.source_ip} | {finding.attempts} başarısız deneme"
            )

    alert_count = sum(item.possible_brute_force for item in findings)
    print(f"\n[INFO] Toplam başarısız SSH denemesi: {len(attempts)}")
    print(f"[INFO] Eşik değerini aşan IP sayısı: {alert_count}")

    if args.json_path:
        write_json(args.json_path, attempts, findings)
        print(f"[INFO] JSON raporu yazıldı: {args.json_path}")
    if args.csv_path:
        write_csv(args.csv_path, findings)
        print(f"[INFO] CSV raporu yazıldı: {args.csv_path}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
