# DevOps / Supply Chain Pack

## Purpose

`carthago.devops.v1` adds optional supply-chain detections for Jenkins abuse, GitHub or GitLab token misuse, package repository anomalies, CI runner secret access, secrets-manager misuse, and suspicious infrastructure automation traffic.

## Rule list

- `DEVOPS001-DEVOPS040`
- Coverage themes: Terraform state exposure, Jenkins and TeamCity probes, PAT leaks, package registry abuse, Vault and secret-manager access, artifact archive downloads, and broker or repository administration exposure.

## Default modes by profile

- `Enterprise`: `Alert` when CI or CD infrastructure is configured.
- `SmallBusiness`: `Shadow`
- `HomeLab`: `Disabled`
- `Research`: `Alert`

## Telemetry requirements

- CI or CD web and API telemetry
- Package repository visibility
- Secret-manager and artifact-store traffic

## Tuning guidance

- Populate approved CI or CD servers before promoting enterprise rules to paging.
- Review package mirror, artifact sync, and secrets-manager automation before loosening noise controls.
- Use benchmark output to separate real registry abuse from legitimate developer workflows.

## Approved asset config

- `Approved.CiCdServers`

## Known false positives

- Legitimate build agents performing artifact syncs or package downloads.
- Approved Terraform and Vault automation.
- Internal registry health checks and broker management tasks.

## Replay benchmark summary

- Positive sample: `devops-jenkins-crumb`
- Benign sample: `normal-browsing`
- Benchmark expectations: enterprise positive pass rate at or above `70%` with zero critical benign spam.

## Response recommendations

- Rotate CI, registry, or Vault credentials after owner approval.
- Collect runner and build logs for corroboration.
- Restrict suspicious publish paths only after validating business ownership.

## Safety notes

- The pack stays effectively disabled until CI or CD infrastructure is configured.
- No automatic repository blocking or token revocation is allowed.
- Historical detections remain durable across pack upgrades and removal.

## References

- MITRE ATT&CK `T1584`
- CISA software supply chain security guidance
- Sigma DevOps guidance
