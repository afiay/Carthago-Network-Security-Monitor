# Cloud / SaaS Pack

## Purpose

`carthago.cloud-saas.v1` expands Carthago with optional cloud and SaaS detections for metadata abuse, storage exfiltration, webhook misuse, OAuth or device-code abuse, and cloud tunnel behavior without forcing every installation into a high-noise cloud catalog.

## Rule list

- `CLOUD001-CLOUD050`
- Coverage themes: GitHub or GitLab raw access, Slack or Discord or Telegram egress, SaaS export behavior, AWS or Azure or GCP metadata abuse, cloud storage anomalies, STS or IAM misuse, tunnel creation, and public cloud CLI patterns.

## Default modes by profile

- `Enterprise`: `Alert` with pack confidence floors applied for higher-risk metadata and credential retrieval detections.
- `SmallBusiness`: `Shadow`
- `HomeLab`: `Shadow`
- `Research`: `Alert`

## Telemetry requirements

- HTTP metadata
- Cloud host enrichment
- Upload directionality
- SaaS API hostnames

## Tuning guidance

- Keep `CLOUD006-CLOUD008` behind high confidence floors before paging.
- Review tenant-specific approved destinations before promoting collaboration API traffic to `Alert`.
- Prefer replay benchmarking before changing bulk upload and export rules from `Shadow` to `Alert`.

## Approved asset config

- Optional cloud storage provider and SaaS ownership allowlists reduce noise.
- Tenant or admin-host knowledge helps separate legitimate OAuth and export workflows from abuse.

## Known false positives

- Approved webhook endpoints used by internal automation.
- Legitimate large uploads to sanctioned cloud storage.
- Security validation labs testing metadata endpoint protections.

## Replay benchmark summary

- Positive samples: `ssrf-imds`, `oauth-device-code-phishing`, `cloudflared-tunnel`
- Benign sample: `normal-cloud-upload-approved`
- Benchmark expectations: enterprise positive pass rate at or above `70%`, research at or above `80%`, with no critical enterprise benign spam.

## Response recommendations

- Review OAuth app consent and device-code use.
- Rotate exposed cloud or API tokens after explicit approval.
- Validate and potentially block suspicious webhook destinations only after owner review.

## Safety notes

- The pack remains effectively disabled when the required cloud or SaaS telemetry is missing.
- Token revocation and destination blocking are never automatic.
- The local JSONL journal remains authoritative for every cloud detection.

## References

- MITRE ATT&CK `T1087.004`
- CISA cloud security technical reference architecture
- Sigma detection content guidance
