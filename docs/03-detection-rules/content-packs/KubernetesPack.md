# Kubernetes / Container Pack

## Purpose

`carthago.kubernetes.v1` adds optional Kubernetes and container detections for API enumeration, pod exec, service-account token access, kubelet access, registry abuse, secrets access, and cluster tunnel behavior.

## Rule list

- `K8S001-K8S040`
- Coverage themes: anonymous API discovery, service-account token access, pod exec, port-forward abuse, kubelet probes, registry pulls or pushes, metadata token requests, and network-policy bypass indicators.

## Default modes by profile

- `Enterprise`: `Alert` when Kubernetes API servers are configured, otherwise non-paging.
- `HomeLab`: `Disabled`
- `Research`: `Alert`

## Telemetry requirements

- Kubernetes API visibility
- Container registry traffic
- Service-account and metadata access telemetry

## Tuning guidance

- Populate approved API servers before promoting the pack into paging modes.
- Validate registry and image pull baselines before relaxing shadow-first defaults.
- Use replay output to identify rules that still need cluster-specific allowlisting.

## Approved asset config

- `Approved.KubernetesApiServers`

## Known false positives

- Platform engineering automation that legitimately uses pod exec or port forward.
- Approved registry mirror sync traffic.
- Cluster health tooling that queries kubelet or namespace metadata.

## Replay benchmark summary

- Positive sample: `kubernetes-pod-exec`
- Benign sample: `normal-browsing`
- Benchmark expectations: enterprise positive pass rate at or above `70%` with zero critical benign spam.

## Response recommendations

- Revoke or rotate service-account tokens after cluster-owner approval.
- Collect API server audit logs and pod exec evidence.
- Consider node cordon only after coordinated review.

## Safety notes

- The pack stays effectively disabled when Kubernetes API context is missing.
- No automatic node cordon, token revocation, or registry blocking is permitted.
- Journaled detections remain durable even if the pack is later disabled.

## References

- MITRE ATT&CK `T1611`
- MITRE ATT&CK `T1528`
- CISA Kubernetes hardening guidance
