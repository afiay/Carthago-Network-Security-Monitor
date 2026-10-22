# Microsoft 365 / Collaboration Pack

## Purpose

`carthago.microsoft365.v1` adds optional compiled Microsoft 365 detections for Exchange or OWA or EWS abuse, Teams or SharePoint or OneDrive anomalies, Graph API exports, webhook misuse, and network-visible OAuth abuse patterns.

## Rule list

- `M365001-M365040`
- Coverage themes: SAML or OIDC callback anomalies, Graph export patterns, mailbox access, webhook abuse, collaboration file exports, and unusual admin portal access.

## Default modes by profile

- `Enterprise`: `Alert` or `Shadow` depending on confidence.
- `SmallBusiness`: `Shadow`
- `HomeLab`: `Shadow`
- `Research`: `Alert`

## Telemetry requirements

- HTTP or HTTPS collaboration telemetry
- M365 auth and Graph visibility
- Mailbox and file export indicators

## Tuning guidance

- Use sanctioned tenant and workload context to tune Graph export noise.
- Keep tenant-wide mailbox export or admin portal detections behind review before paging in smaller environments.
- Benchmark device-code and collaboration export samples before changing default modes.

## Approved asset config

- Tenant-specific collaboration domains, service principals, and admin workflows are the most useful allowlist inputs.

## Known false positives

- Approved file export jobs or migration workflows.
- Legitimate SharePoint or OneDrive synchronization bursts.
- Security validation exercises against Microsoft login infrastructure.

## Replay benchmark summary

- Positive sample: `oauth-device-code-phishing`
- Benign sample: `normal-browsing`
- Benchmark expectations: enterprise positive pass rate at or above `70%` with zero critical benign spam.

## Response recommendations

- Review OAuth consent and device-code activity.
- Pull Exchange, SharePoint, OneDrive, and Graph audit logs.
- Reset credentials only after tenant-owner approval.

## Safety notes

- Tenant-wide permission changes are never automatic.
- Collaboration detections remain advisory-first until tenant-specific tuning is reviewed.
- The local detection journal remains the durable record of all pack events.

## References

- MITRE ATT&CK `T1567`
- CISA SCuBA guidance
- Sigma identity and cloud SaaS guidance
