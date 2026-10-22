# Exfiltration Pack

## Purpose

`carthago.exfiltration.v1` adds optional exfiltration detections for archive staging, database dump transfers, cloud storage upload bursts, split exfiltration, low-and-slow egress, suspicious CLI upload tooling, and encrypted uploads after internal sweeps.

## Rule list

- `EXFIL001-EXFIL040`
- Coverage themes: first-time cloud uploads, personal cloud storage, internal sweep followed by upload, split exfiltration, archive and dump transfers, repeated small chunk uploads, rclone or Mega-like tooling, and sensitive file uploads.

## Default modes by profile

- `Enterprise`: `Alert` or `Shadow` depending on confidence.
- `SmallBusiness`: `Shadow`
- `HomeLab`: `Shadow`
- `Research`: `Alert`

## Telemetry requirements

- Upload ratio and byte counts
- HTTP or HTTPS upload telemetry
- Archive and sensitive-file indicators

## Tuning guidance

- Calibrate upload-ratio thresholds using sanctioned backup and sync workflows.
- Keep bulk archive and database export signals benchmarked before widening alerting.
- Use explicit allowlists for approved cloud storage and destination domains where possible.

## Approved asset config

- Approved cloud storage providers
- Known backup destinations and synchronization hosts

## Known false positives

- Approved backup or replication jobs.
- Sanctioned developer artifact uploads.
- Large but legitimate collaboration file transfers.

## Replay benchmark summary

- Positive sample: `rclone-exfil`
- Benign sample: `normal-cloud-upload-approved`
- Benchmark expectations: enterprise positive pass rate at or above `75%` with zero critical benign spam.

## Response recommendations

- Preserve packet and archive evidence before containment.
- Recommend host isolation only after validating business impact.
- Recommend blocking suspicious destinations only after analyst review.

## Safety notes

- No automatic destructive network action is permitted.
- The local detection journal remains authoritative for all exfiltration findings.
- Historical detections and evidence remain durable across disable and uninstall actions.

## References

- MITRE ATT&CK `T1567`
- MITRE ATT&CK `T1041`
- Sigma exfiltration guidance
