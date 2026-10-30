# Network Threat Hunting & Anomaly Detection

### Network Threat Hunting & Anomaly Detection

**NTH // SIGNAL** is a local-first network threat-hunting utility that analyzes network-flow records and packet captures, applies explainable behavioral detection rules, correlates optional local threat-intelligence indicators, and generates an interactive HTML investigation report with a machine-readable JSON output.

It is designed to help security analysts move from raw network telemetry to structured, evidence-backed investigation leads.

> **Current version:** `2.0.0-dev.1`  
> **Project status:** Active development  
> **Runtime:** Python 3.10+  
> **Dependencies:** Python standard library only

---

## Overview

Network telemetry can contain useful signs of suspicious activity, but individual indicators rarely tell the whole story. Unusual traffic volume, repeated connection attempts, periodic communication, suspicious DNS patterns, and threat-intelligence matches all require context.

NTH // SIGNAL brings these observations into one analysis workflow:

1. Ingest network-flow exports, Zeek logs, or supported PCAP/PCAPNG captures.
2. Normalize available network metadata into a consistent flow representation.
3. Apply configurable, explainable detection rules.
4. Assess severity, confidence, and investigation priority separately.
5. Optionally match IP addresses and domains against a locally supplied IOC list.
6. Generate an interactive HTML report and optional JSON findings export.

The tool is intended for offline analysis of supplied telemetry. It is not currently a live network sensor, packet-capture daemon, SIEM, or automated incident-response platform.

---

## Key capabilities

| Area | Current capability |
|---|---|
| Telemetry ingestion | CSV, TSV, Zeek logs, PCAP, and PCAPNG |
| Flow analysis | Bidirectional endpoint-pair aggregation for supported packet captures |
| Behavioral hunting | Scanning, repeated failures, beacon-like timing, volume, duration, and DNS heuristics |
| Threat intelligence | Local IP/domain IOC matching without reputation-service lookups |
| Evidence | Structured evidence records with source, rule ID, version, entities, and observation details |
| Risk assessment | Separate severity, confidence, and priority fields |
| ATT&CK context | Conservative MITRE ATT&CK technique candidates for selected network behaviors |
| Configuration | Validated JSON configuration for thresholds, ports, and disabled rules |
| Reporting | Interactive standalone HTML report and optional JSON export |
| Testing | Automated unit and regression tests using Python's `unittest` |

### Detection coverage

NTH // SIGNAL currently includes rules for:

- High-risk destination ports.
- Sensitive service exposure.
- Unsuccessful connections.
- Repeated connection failures.
- Horizontal network scanning.
- Vertical port scanning.
- Distributed probing patterns.
- Regular connection-timing patterns that may resemble beaconing.
- Outbound traffic-volume outliers.
- Long-lived flows.
- Large asymmetric transfers that may warrant data-staging or exfiltration investigation.
- Long DNS query names.
- High-entropy DNS labels.
- Matches against a supplied local IOC list.

These rules identify **investigation leads**, not proof of compromise. A port, traffic pattern, DNS characteristic, or IOC match must be interpreted in the context of the environment and corroborated with additional telemetry.

---

## How the analysis works

```text
  Network telemetry
  ├── CSV / TSV flow exports
  ├── Zeek logs
  └── PCAP / PCAPNG
          |
          v
  Ingestion and normalization
          |
          v
  Normalized network flows
          |
          v
  Configurable detection rules
  ├── Behavioral analysis
  ├── DNS heuristics
  ├── Connection and scan analysis
  ├── Volume and duration analysis
  └── Local IOC matching
          |
          v
  Evidence and risk assessment
  ├── Severity
  ├── Confidence
  ├── Priority score
  ├── Rule metadata
  └── ATT&CK candidates
          |
          v
  Analyst outputs
  ├── Interactive HTML report
  └── JSON findings export
```

### Severity, confidence, and priority

NTH // SIGNAL deliberately treats these as separate dimensions:

| Field | Meaning |
|---|---|
| **Severity** | Potential impact represented by the detection rule |
| **Confidence** | Strength of the available observations supporting the finding |
| **Priority** | Suggested analyst queue band based on the calculated priority score |

The priority score is not a probability that an event is malicious. It is a configurable triage aid.

The current scoring approach uses the strongest signal weight, adds a configurable corroboration bonus for distinct evidence groups, and caps the result at 100. Severity is mapped from detection rules rather than inferred from the priority score. Confidence summarizes the supporting signals.

### IOC assessment

Local IOC matches are assessed using available feed metadata:

- Indicator confidence.
- Source/provenance.
- Optional `last_seen` timestamp.
- Optional `expires_at` timestamp.

An IOC match by itself is capped below Critical priority. If freshness metadata is absent, freshness is treated as **Unknown**, not automatically stale. The analysis timestamp is used as the scoring reference time.

No external reputation or threat-intelligence service is queried.

### Evidence and rule metadata

Findings include structured evidence and stable rule identifiers/versions. The JSON export includes a top-level `findings` collection, alongside normalized flow data. The legacy `score` field remains available as a compatibility alias for `priority_score`.

ATT&CK mappings are intentionally conservative. A mapping is a candidate for analyst consideration, not confirmation that a technique occurred.

---

## Quick start

### Requirements

- Python 3.10 or newer.
- No third-party Python packages are required.
- A terminal or command prompt.

### 1. Get the project

Clone the repository:

```bash
git clone <YOUR-GITHUB-REPOSITORY-URL>
cd <YOUR-REPOSITORY-DIRECTORY>
```

Alternatively, download and extract the project ZIP, then open a terminal in the extracted project directory.

### 2. Check the version

```bash
python app.py --version
```

### 3. Generate a demonstration report

```bash
python app.py --demo --output demo_report.html --json-output demo_findings.json
```

Open `demo_report.html` in a browser.

The demonstration uses synthetic data. Its reserved example IP addresses and domains are not live malicious infrastructure.

### 4. Analyze a supported input

CSV example:

```bash
python app.py flows.csv --output analysis_report.html
```

Zeek example:

```bash
python app.py conn.log --output zeek_report.html
```

PCAP example:

```bash
python app.py capture.pcap --output pcap_report.html
```

PCAPNG example:

```bash
python app.py capture.pcapng --output pcapng_report.html
```

Generate HTML and JSON together:

```bash
python app.py capture.pcapng \
  --output analysis_report.html \
  --json-output findings.json
```

On Windows PowerShell, the same command can be entered on one line:

```powershell
python .\app.py .\capture.pcapng -o .\analysis_report.html --json-output .\findings.json
```

---

## Command-line reference

```text
python app.py [INPUT] [OPTIONS]
```

| Argument | Description |
|---|---|
| `INPUT` | CSV, TSV, Zeek log, PCAP, or PCAPNG file |
| `-o`, `--output PATH` | HTML report path; defaults to `nth_report.html` |
| `--json-output PATH` | Also export normalized flows and findings as JSON |
| `--config PATH` | Load detection thresholds and rule configuration from JSON |
| `--write-default-config PATH` | Write a starter configuration file and exit |
| `--iocs PATH` | Load a local IOC CSV file |
| `--demo` | Analyze synthetic demonstration data |
| `--version` | Display the project version |
| `-h`, `--help` | Display command help |

Examples:

```bash
# Display help
python app.py --help

# Write a starter detection configuration
python app.py --write-default-config detection_config.json

# Analyze with custom thresholds
python app.py flows.csv --config detection_config.json -o report.html

# Analyze with a local IOC list
python app.py capture.pcap --iocs iocs.csv -o report.html

# Use both custom configuration and local IOCs
python app.py capture.pcapng \
  --config detection_config.json \
  --iocs iocs.csv \
  --output investigation.html \
  --json-output findings.json
```

The CLI validates configuration values and prevents the HTML/JSON outputs from overwriting the input file or each other.

---

## Input formats

### CSV and TSV flow exports

Delimited files must contain source and destination IP address columns. Header matching is case-insensitive and normalizes spaces and punctuation. Common field names from Zeek and CICFlowMeter-style exports are recognized.

Commonly recognized fields include:

| Normalized field | Example accepted headers |
|---|---|
| Timestamp | `timestamp`, `ts`, `time`, `starttime` |
| Source IP | `src_ip`, `srcip`, `id.orig_h`, `source` |
| Destination IP | `dst_ip`, `dstip`, `id.resp_h`, `destination` |
| Source port | `src_port`, `srcport`, `id.orig_p` |
| Destination port | `dst_port`, `dstport`, `id.resp_p`, `port` |
| Protocol | `protocol`, `proto`, `ip_proto` |
| Duration | `duration`, `dur`, `flow_duration` |
| Source bytes | `src_bytes`, `orig_bytes`, `bytes_sent` |
| Destination bytes | `dst_bytes`, `resp_bytes`, `bytes_received` |
| Source packets | `src_packets`, `orig_pkts`, `total_fwd_packets` |
| Destination packets | `dst_packets`, `resp_pkts`, `total_backward_packets` |
| Connection state | `conn_state`, `state`, `connection_state` |
| DNS query | `dns_query`, `query`, `qname`, `domain` |

A minimal CSV example:

```csv
timestamp,src_ip,dst_ip,src_port,dst_port,protocol,duration,src_bytes,dst_bytes,conn_state
2026-10-30T09:00:00Z,10.0.0.15,203.0.113.20,51520,443,TCP,12.4,4200,18200,ESTABLISHED
2026-10-30T09:01:00Z,10.0.0.15,203.0.113.21,51521,443,TCP,8.2,3100,9700,ESTABLISHED
```

The addresses above are documentation-only examples.

### Zeek logs

Zeek logs with a `#fields` header are supported. The parser recognizes connection and DNS fields, including common `conn.log` and `dns.log` layouts.

```bash
python app.py conn.log -o zeek_connections.html
python app.py dns.log -o zeek_dns.html
```

### PCAP and PCAPNG

The built-in parser supports the currently implemented packet formats and network layers:

- Classic PCAP and PCAPNG.
- Ethernet frames and VLAN tags.
- Linux cooked capture.
- Raw IPv4 and IPv6 link types.
- TCP and UDP transport metadata.
- DNS question extraction over UDP.

The current parser groups packets by bidirectional endpoint pair to produce flow summaries. This is not full TCP session reconstruction.

**Current packet-analysis limitations:**

- Fragmented IP packets are not reassembled.
- Encrypted application payloads are not decrypted or inspected.
- DNS over TCP is not parsed.
- Not every PCAP link type is supported.
- Application-layer session reconstruction is not implemented.
- Packet capture processing is not a real-time streaming sensor.

For large captures, consider exporting flow or connection telemetry with an established tool such as Zeek before analysis.

---

## Local threat-intelligence matching

NTH // SIGNAL can match network observations against a local CSV indicator list. This keeps indicator matching self-contained and avoids sending private telemetry to an external service.

Start with the included template:

```text
iocs.example.csv
```

Example:

```csv
indicator,type,source,confidence,notes,last_seen,expires_at
198.51.100.27,ipv4,Example Feed,medium,Example indicator,2026-10-01T00:00:00Z,
example.test,domain,Internal Research,high,Test domain,,2026-12-01T00:00:00Z
```

Supported columns:

| Column | Required | Description |
|---|---|---|
| `indicator` | Yes | IP address or domain |
| `type` | No | `ip`, `ipv4`, `ipv6`, `ip-address`, `domain`, `hostname`, or `fqdn` |
| `source` | No | Feed or source name |
| `confidence` | No | Feed confidence label |
| `notes` | No | Analyst context |
| `last_seen` | No | Last-seen timestamp |
| `expires_at` | No | Indicator expiry timestamp |

Timestamps should use ISO 8601 format. IP indicators are matched against either flow endpoint. Domain indicators match the exact queried name and subdomains.

Run IOC matching:

```bash
python app.py capture.pcap \
  --iocs iocs.csv \
  --output ioc_investigation.html \
  --json-output ioc_findings.json
```

Only use IOC data you are authorized to process. Validate indicator provenance and freshness before treating a match as meaningful.

---

## Detection configuration

Generate a starter configuration:

```bash
python app.py --write-default-config detection_config.json
```

The included `detection_config.example.json` documents the available configuration structure.

Current configuration areas include:

- Outbound volume outlier thresholds.
- Long-flow duration.
- Large-transfer and asymmetry thresholds.
- Horizontal, vertical, and distributed scan thresholds and time windows.
- Failed-connection thresholds and time windows.
- Beacon observation counts, timing ranges, and interval variation.
- DNS query length and entropy thresholds.
- High-risk and sensitive port descriptions.
- Disabled detection rules.
- Priority cutoffs and IOC scoring controls.
- IOC confidence factors, freshness decay, and corroboration bonus.

Example:

```json
{
  "beacon_min_observations": 6,
  "beacon_min_interval_seconds": 10.0,
  "beacon_max_interval_seconds": 3600.0,
  "beacon_max_gap_cv": 0.15,
  "critical_score": 75,
  "high_score": 50,
  "medium_score": 25,
  "disabled_rules": []
}
```

This is an illustrative partial configuration. For a complete valid configuration, generate the file using `--write-default-config` or start from `detection_config.example.json`.

Unknown configuration keys, invalid rule names, and invalid values are rejected rather than silently ignored.

---

## Understanding the HTML report

The generated report is a standalone HTML file intended for local analyst review.

It includes:

- Analysis summary and finding counts.
- Severity, confidence, and priority information.
- Searchable and filterable flow/finding views.
- Detection explanations and supporting evidence.
- Rule identifiers and versions.
- Local IOC match context.
- Candidate MITRE ATT&CK mappings.
- Investigation status and analyst notes.
- JSON case export for analyst notes.
- A print-friendly layout that can be saved as PDF through the browser.

Analyst notes are held in the browser while reviewing the report. Export them using the report's **Export case JSON** action if they need to be retained. They are not automatically written back to the original source file.

The report is generated locally. It does not upload capture data. Selecting an ATT&CK reference opens the corresponding MITRE ATT&CK website.

---

## Testing

Run the test suite from the repository root:

```bash
python -m unittest discover -v
```

The current development baseline contains **29 passing unit tests**. These tests cover areas including:

- CSV and TSV header normalization.
- Zeek connection and DNS log normalization.
- Classic PCAP and PCAPNG parsing.
- Supported raw IPv4 link type handling.
- DNS question extraction and malformed/truncated input handling.
- Invalid IP row handling.
- IOC validation, confidence, and expiry behavior.
- Beacon timing and scan-window logic.
- Repeated connection-failure grouping.
- Separation of severity, confidence, and priority.
- Legacy `score` compatibility.
- Configuration validation.
- HTML report controls and safe embedding of source-name text.

Test count is a development snapshot, not a detection-accuracy or production-readiness metric. Passing unit tests do not establish the quality of detections on a representative enterprise network.

---

## Project structure

```text
.
├── app.py
├── NTH_AD.py
├── CHANGELOG.md
├── README.md
├── detection_config.example.json
├── iocs.example.csv
├── nth_signal/
│   ├── __init__.py
│   ├── cli.py
│   ├── config.py
│   ├── detection.py
│   ├── ingestion.py
│   ├── intel.py
│   ├── mitre.py
│   ├── models.py
│   ├── pcap.py
│   ├── report.py
│   └── report_template.html
└── tests/
    ├── __init__.py
    └── test_nth_signal.py
```

| File | Responsibility |
|---|---|
| `app.py` | Primary command-line entry point |
| `NTH_AD.py` | Backward-compatible entry point and exports |
| `nth_signal/cli.py` | Argument parsing and analysis orchestration |
| `nth_signal/ingestion.py` | CSV, TSV, and Zeek log ingestion |
| `nth_signal/pcap.py` | PCAP/PCAPNG packet parsing and flow aggregation |
| `nth_signal/detection.py` | Behavioral rules, evidence generation, and risk assessment |
| `nth_signal/models.py` | Structured finding and evidence records |
| `nth_signal/config.py` | Detection configuration and validation |
| `nth_signal/intel.py` | Local IOC loading and matching |
| `nth_signal/mitre.py` | Conservative ATT&CK candidate mappings |
| `nth_signal/report.py` | Demo data, report payload, and HTML rendering |
| `nth_signal/report_template.html` | Standalone HTML report interface |
| `tests/` | Automated unit and regression tests |

---

## Security, privacy, and responsible use

- Analyze only network data you own or are explicitly authorized to examine.
- Treat detections as leads that require analyst validation.
- Do not interpret a single heuristic or IOC match as proof of compromise.
- Protect PCAP files, IOC lists, reports, and exported findings as potentially sensitive security data.
- Review generated reports before sharing them; they may contain internal IP addresses, domains, host metadata, and investigation notes.
- Use synthetic or sanitized telemetry in public demonstrations.
- No external IOC reputation lookups are performed by the current implementation.

NTH // SIGNAL is an analysis aid. It does not block traffic, isolate endpoints, modify firewall rules, or perform automated remediation.

---

## Current limitations and development direction

NTH // SIGNAL is under active development. The following are not represented as completed capabilities:

- Full IP fragment reassembly.
- Full TCP stream or application-session reconstruction.
- Streaming PCAP ingestion and large-capture performance guarantees.
- Multi-event incident correlation across a host timeline.
- Network relationship graph and full case-management workflow.
- Live packet capture and continuous monitoring.
- Endpoint, identity, or cloud telemetry correlation.
- Validated detection benchmarks across public datasets and representative enterprise traffic.
- Machine-learning-based anomaly detection.

Planned engineering work includes more robust packet/session handling, broader telemetry integrations, stronger detection validation, event correlation, and an expanded analyst investigation experience. These items will be marked complete only after implementation and testing.

---

## Contributing

Contributions, issue reports, and detection-rule improvements are welcome.

When proposing a detection change, include:

1. The behavior the rule is intended to identify.
2. Required input fields and assumptions.
3. A benign example and a suspicious example.
4. Supporting evidence and known limitations.
5. Unit tests that cover expected behavior and false-positive edge cases.
6. Any configuration changes and documentation updates.

Keep detection logic explainable and avoid claims of confirmed compromise based solely on network heuristics.

---

## Author

**Chandrashekar Bala**  
Cybersecurity | Network Threat Hunting | Detection Engineering

- **GitHub:** https://github.com/Chandrashekar-Bala

---

## License

No license is currently specified in this repository. Unless and until a license is added, reuse, redistribution, and modification are not granted by default. Add an appropriate `LICENSE` file before inviting external contributions or presenting the project as open source.

---

**NTH // SIGNAL — From network telemetry to evidence-backed investigation leads.**
