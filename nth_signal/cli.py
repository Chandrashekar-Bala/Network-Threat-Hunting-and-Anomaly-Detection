"""Command line interface for NTH // Signal."""

from __future__ import annotations

import argparse
import csv
import json
import sys
from pathlib import Path

from nth_signal import __version__
from nth_signal.config import DetectionConfig, write_default_config
from nth_signal.detection import analyze
from nth_signal.ingestion import read_flows
from nth_signal.intel import load_iocs
from nth_signal.pcap import read_pcap
from nth_signal.report import demo_flows, render_html, report_payload


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Review network flow records and build a local investigation report.",
        epilog=(
            "Examples: python app.py flows.csv -o report.html; "
            "python app.py capture.pcapng --config rules.json --iocs iocs.csv"
        ),
    )
    parser.add_argument("--version", action="version", version=f"NTH // Signal {__version__}")
    parser.add_argument("input", nargs="?", help="CSV, TSV, Zeek log, PCAP, or PCAPNG file")
    parser.add_argument("-o", "--output", default="nth_report.html", help="HTML report path")
    parser.add_argument("--json-output", help="Also save normalized flows and findings as JSON")
    parser.add_argument("--config", help="Read detection thresholds from a JSON file")
    parser.add_argument("--write-default-config", metavar="PATH", help="Write starter thresholds and exit")
    parser.add_argument("--iocs", help="Load a local CSV indicator list; no network lookups are made")
    parser.add_argument("--demo", action="store_true", help="Use synthetic data to preview the report")
    return parser


def main() -> int:
    parser = build_parser()
    args = parser.parse_args()

    if args.write_default_config:
        try:
            path = Path(args.write_default_config).expanduser()
            write_default_config(path)
            print(f"Starter configuration written to {path.resolve()}")
            return 0
        except OSError as exc:
            print(f"Could not write configuration: {exc}", file=sys.stderr)
            return 1

    if args.demo and args.input:
        parser.error("Choose either an input file or --demo, not both.")
    if not args.demo and not args.input:
        parser.print_help()
        return 2

    try:
        config = (
            DetectionConfig.from_file(Path(args.config).expanduser())
            if args.config
            else DetectionConfig()
        )
        iocs = load_iocs(Path(args.iocs).expanduser()) if args.iocs else {}

        if args.demo:
            flows = demo_flows()
            source = "demo_capture"
            source_format = "Synthetic demonstration"
            input_path = None
        else:
            input_path = Path(args.input).expanduser()
            if input_path.suffix.casefold() in {".pcap", ".pcapng", ".cap"}:
                flows = read_pcap(input_path)
                source_format = (
                    "PCAPNG packet capture"
                    if input_path.suffix.casefold() == ".pcapng"
                    else "PCAP packet capture"
                )
            else:
                flows, source_format = read_flows(input_path)
            source = input_path.name

        html_path = Path(args.output).expanduser()
        json_path = Path(args.json_output).expanduser() if args.json_output else None
        protected_paths = {html_path.resolve()}
        if input_path:
            protected_paths.add(input_path.resolve())
        if json_path and json_path.resolve() in protected_paths:
            raise ValueError("JSON output must use a different path from the input and HTML report.")
        if input_path and html_path.resolve() == input_path.resolve():
            raise ValueError("HTML report must use a different path from the input file.")

        analyzed = analyze(flows, config=config, iocs=iocs)
        payload = report_payload(
            analyzed,
            source,
            source_format,
            critical_threshold=config.critical_score,
        )
        html_path.parent.mkdir(parents=True, exist_ok=True)
        html_path.write_text(render_html(payload), encoding="utf-8")

        if json_path:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )

        meta = payload["meta"]
        print(f"Analyzed {meta['flow_count']:,} flows from {source} ({source_format}).")
        print(f"Flagged {meta['incident_count']:,}; critical priority: {meta['critical_count']:,}.")
        print(f"Local IOC matches: {meta['ioc_match_count']:,}.")
        print(f"HTML report: {html_path.resolve()}")
        if json_path:
            print(f"JSON report: {json_path.resolve()}")
        return 0
    except (OSError, UnicodeError, ValueError, csv.Error) as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1
