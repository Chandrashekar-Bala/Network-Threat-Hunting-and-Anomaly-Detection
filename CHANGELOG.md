# Changelog

## 2.0.0-dev.1

- Added structured finding and evidence records while keeping the flow-based JSON fields.
- Added rule IDs, rule versions, mapped severity, confidence, and priority scoring.
- Made IOC priority depend on feed confidence, source provenance, and optional `last_seen` and `expires_at` dates.
- Added IOC scoring and corroboration controls to the example configuration.
- Updated the HTML report to show severity, confidence, priority, and rule IDs.
- Added regression coverage for IOC confidence, expired indicators, findings, and the legacy `score` field.
