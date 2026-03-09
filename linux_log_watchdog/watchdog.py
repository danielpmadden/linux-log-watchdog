from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
import json
from pathlib import Path
import re
import time
from typing import Dict, Iterable, Iterator, List, Optional, Pattern


TIMESTAMP_PATTERN = re.compile(
    r"^(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<hour>\d{2}):(?P<minute>\d{2}):(?P<second>\d{2})"
)


@dataclass
class PatternRule:
    name: str
    regex: str
    description: str = ""
    compiled: Pattern[str] = field(init=False, repr=False)

    def __post_init__(self) -> None:
        self.compiled = re.compile(self.regex, re.IGNORECASE)


@dataclass
class MatchRecord:
    pattern_name: str
    log_file: str
    line_number: int
    timestamp: Optional[str]
    line: str


@dataclass
class ScanSummary:
    started_at: str
    ended_at: str
    files_scanned: List[str]
    counts: Dict[str, int]
    matches: Dict[str, List[MatchRecord]]

    def as_dict(self) -> Dict[str, object]:
        return {
            "started_at": self.started_at,
            "ended_at": self.ended_at,
            "files_scanned": self.files_scanned,
            "counts": self.counts,
            "matches": {
                name: [
                    {
                        "log_file": item.log_file,
                        "line_number": item.line_number,
                        "timestamp": item.timestamp,
                        "line": item.line,
                    }
                    for item in records
                ]
                for name, records in self.matches.items()
            },
        }

    def to_json(self) -> str:
        return json.dumps(self.as_dict(), indent=2)

    def to_text(self) -> str:
        lines: List[str] = [
            "Linux Log Watchdog Summary",
            "=" * 27,
            f"Started: {self.started_at}",
            f"Ended:   {self.ended_at}",
            f"Files:   {', '.join(self.files_scanned)}",
            "",
            "Pattern Counts:",
        ]

        for pattern, count in self.counts.items():
            lines.append(f"- {pattern}: {count}")

        lines.append("\nMatched Lines:")
        for pattern, records in self.matches.items():
            lines.append(f"\n[{pattern}] ({len(records)} match(es))")
            for record in records:
                timestamp = record.timestamp or "timestamp not parsed"
                lines.append(
                    f"  - {record.log_file}:{record.line_number} | {timestamp} | {record.line}"
                )
        return "\n".join(lines)


DEFAULT_PATTERNS: List[PatternRule] = [
    PatternRule(
        name="failed_ssh_login",
        regex=r"Failed password for|authentication failure|Invalid user",
        description="Failed SSH or PAM authentication attempts",
    ),
    PatternRule(
        name="service_error",
        regex=r"\b(error|failed|fatal|panic)\b",
        description="General service failures and fatal errors",
    ),
    PatternRule(
        name="disk_warning",
        regex=r"(I/O error|disk full|out of space|EXT4-fs warning|SMART error)",
        description="Disk and filesystem warning indicators",
    ),
]


class LogWatchdog:
    def __init__(self, patterns: Iterable[PatternRule]) -> None:
        self.patterns = list(patterns)

    @staticmethod
    def load_patterns_from_json(path: Path) -> List[PatternRule]:
        payload = json.loads(path.read_text())
        return [
            PatternRule(
                name=item["name"],
                regex=item["regex"],
                description=item.get("description", ""),
            )
            for item in payload
        ]

    @staticmethod
    def parse_timestamp(line: str, year: Optional[int] = None) -> Optional[str]:
        match = TIMESTAMP_PATTERN.match(line)
        if not match:
            return None

        year = year or datetime.now().year
        timestamp = f"{year} {match.group('month')} {match.group('day')} {match.group('hour')}:{match.group('minute')}:{match.group('second')}"
        try:
            parsed = datetime.strptime(timestamp, "%Y %b %d %H:%M:%S")
            return parsed.isoformat()
        except ValueError:
            return None

    def _evaluate_line(
        self, line: str, log_file: str, line_number: int, matches: Dict[str, List[MatchRecord]]
    ) -> None:
        for pattern in self.patterns:
            if pattern.compiled.search(line):
                matches[pattern.name].append(
                    MatchRecord(
                        pattern_name=pattern.name,
                        log_file=log_file,
                        line_number=line_number,
                        timestamp=self.parse_timestamp(line),
                        line=line.rstrip(),
                    )
                )

    def scan_files(self, files: Iterable[Path]) -> ScanSummary:
        started_at = datetime.utcnow().isoformat()
        target_files = [str(file) for file in files]
        matches: Dict[str, List[MatchRecord]] = {rule.name: [] for rule in self.patterns}

        for path in files:
            with path.open("r", encoding="utf-8", errors="replace") as handle:
                for line_number, line in enumerate(handle, start=1):
                    self._evaluate_line(line, str(path), line_number, matches)

        ended_at = datetime.utcnow().isoformat()
        counts = {name: len(records) for name, records in matches.items()}
        return ScanSummary(started_at, ended_at, target_files, counts, matches)

    def follow_files(
        self, files: Iterable[Path], duration_seconds: Optional[int] = None, poll_interval: float = 0.5
    ) -> Iterator[MatchRecord]:
        paths = [Path(f) for f in files]
        handles = [path.open("r", encoding="utf-8", errors="replace") for path in paths]
        line_numbers = {str(path): 0 for path in paths}

        try:
            for index, handle in enumerate(handles):
                for _ in handle:
                    line_numbers[str(paths[index])] += 1

            start = time.time()
            while True:
                for index, handle in enumerate(handles):
                    line = handle.readline()
                    while line:
                        log_file = str(paths[index])
                        line_numbers[log_file] += 1
                        matches: Dict[str, List[MatchRecord]] = {
                            rule.name: [] for rule in self.patterns
                        }
                        self._evaluate_line(line, log_file, line_numbers[log_file], matches)
                        for bucket in matches.values():
                            for record in bucket:
                                yield record
                        line = handle.readline()

                if duration_seconds is not None and (time.time() - start) >= duration_seconds:
                    break
                time.sleep(poll_interval)
        finally:
            for handle in handles:
                handle.close()
