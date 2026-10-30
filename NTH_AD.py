#!/usr/bin/env python3
"""Compatibility entry point for NTH // Signal."""

from nth_signal.cli import main
from nth_signal.detection import analyze, robust_outliers
from nth_signal.ingestion import read_flows, read_zeek
from nth_signal.pcap import read_pcap
from nth_signal.report import demo_flows, render_html, report_payload

if __name__ == "__main__":
    raise SystemExit(main())
