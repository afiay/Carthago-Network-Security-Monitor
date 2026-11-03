# Active Directory / Windows Enterprise Pack

## Purpose

`carthago.active-directory.v1` adds optional compiled enterprise identity coverage for Kerberos, LDAP, NTLM, SMB admin abuse, WinRM or WMI or DCOM lateral movement, and workstation-to-workstation admin protocol misuse.

## Rule list

- `AD001-AD050`
- Coverage themes: RDP lateral movement, PowerShell remoting, LDAP enumeration, Kerberos anomalies, NTLM relay indicators, remote registry, scheduled tasks, and MSSQL admin abuse.

## Default modes by profile

- `Enterprise`: `Alert` or `Shadow` depending on confidence and approved domain-controller context.
- `SmallBusiness`: `Shadow`
- `HomeLab`: `Disabled`
- `Research`: `Alert`

## Telemetry requirements

- Windows auth protocol metadata
- Kerberos and LDAP visibility
- Admin-host inventory
- Domain-controller enrichment

## Tuning guidance

- Keep approved admin hosts and domain controllers populated before enabling broader paging.
- Use replay samples to validate PowerShell remoting and lateral-movement thresholds.
- Preserve explicit `rules.json` overrides for admin protocols during upgrades.

## Approved asset config

- `Approved.DomainControllers`
- `Approved.AdminHosts`

## Known false positives

- Approved jump hosts using RDP or WinRM.
- Security assessment tooling running from sanctioned admin workstations.
- Password policy or LDAP inventory tasks executed by approved directory services.

## Replay benchmark summary

- Positive sample: `ad-psremoting-encoded-command`
- Benign sample: `normal-admin-rdp-from-adminhost`
- Benchmark expectations: enterprise positive pass rate at or above `70%` with zero critical benign false positives.

## Response recommendations

- Review whether the suspected account should be disabled or constrained.
- Recommend host isolation only after evidence review.
- Collect domain-controller logs and journal-linked evidence bundles.

## Safety notes

- Home-lab deployments stay disabled until explicit domain-controller context exists.
- Directory or host containment actions are recommendation-only or approval-gated.
- Historical detections survive disable and uninstall operations.

## References

- MITRE ATT&CK remote services
- MITRE ATT&CK `T1558`
- Sigma Windows lateral-movement guidance
