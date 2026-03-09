from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import List

from .watchdog import DEFAULT_PATTERNS, LogWatchdog, PatternRule


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="linux-log-watchdog",
        description="Scan and follow Linux logs for security and infrastructure issues.",
    )
    parser.add_argument(
        "--log",
        dest="logs",
        action="append",
        required=True,
        help="Path to a log file. Repeat for multiple files.",
    )
    parser.add_argument(
        "--mode",
        choices=["scan", "follow"],
        default="scan",
        help="scan = one-time read, follow = tail new lines.",
    )
    parser.add_argument(
        "--config",
        type=Path,
        help="JSON file containing a pattern list. Overrides defaults unless --pattern is used.",
    )
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Inline pattern in the form name::regex (can be repeated).",
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=30,
        help="Seconds to run in follow mode (default: 30).",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Emit structured JSON output in scan mode.",
    )
    return parser


def parse_inline_patterns(pattern_args: List[str]) -> List[PatternRule]:
    rules: List[PatternRule] = []
    for raw in pattern_args:
        if "::" not in raw:
            raise ValueError(f"Invalid pattern format: {raw}. Use name::regex")
        name, regex = raw.split("::", maxsplit=1)
        rules.append(PatternRule(name=name.strip(), regex=regex.strip()))
    return rules


def resolve_patterns(config: Path | None, inline_patterns: List[str]) -> List[PatternRule]:
    if inline_patterns:
        return parse_inline_patterns(inline_patterns)
    if config:
        return LogWatchdog.load_patterns_from_json(config)
    return DEFAULT_PATTERNS


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    files = [Path(item) for item in args.logs]
    missing = [str(path) for path in files if not path.exists()]
    if missing:
        raise SystemExit(f"Log files not found: {', '.join(missing)}")

    watchdog = LogWatchdog(resolve_patterns(args.config, args.pattern))

    if args.mode == "scan":
        summary = watchdog.scan_files(files)
        if args.json:
            print(json.dumps(summary.as_dict(), indent=2))
        else:
            print(summary.to_text())
        return

    print(f"Following logs for {args.duration} seconds...\n")
    for match in watchdog.follow_files(files, duration_seconds=args.duration):
        stamp = match.timestamp or "timestamp not parsed"
        print(
            f"[{match.pattern_name}] {match.log_file}:{match.line_number} | {stamp} | {match.line}"
        )


if __name__ == "__main__":
    main()
