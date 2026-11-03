# Replay accuracy: supported detections vs trusted-producer gaps

**SOURCE CANDIDATE — UNVERIFIED. TESTS AUTHORED — 0 EXECUTED.**

Date: 2026-11-03

## Purpose

The replay benchmark now separates three different questions that were previously
mixed into one malicious false-negative count:

1. **Supported malicious detection** — Carthago currently has the telemetry and
   trusted evidence producer needed to evaluate the intended detector.
2. **Unsupported malicious coverage** — the behavior is malicious, but the
   intended detector deliberately fails closed because an authenticated/trusted
   producer is not yet available.
3. **Alert policy** — a supported detector can match correctly and still remain
   Shadow/Disabled because of confidence, baseline, profile, or environment
   policy.

`UnsupportedMalicious` samples are excluded from supported detector and
alert-recall denominators. They are not ignored: each must name the intended
rule and a stable fail-closed reason code. The benchmark fails if that rule
unexpectedly matches or fails closed for a different reason.

No confidence floor, runtime mode, detection threshold, or frozen holdout was
changed by this reclassification.

## Reclassified producer-limited scenarios

| Replay | Rule | Required fail-closed reason |
| --- | --- | --- |
| OAuth device-code phishing | R275 | `TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE` |
| Kubernetes pod exec | R295 | `K8S_POD_EXEC_AUDIT_UNAVAILABLE` |
| PowerShell remoting encoded command | R343 | `WINRM_COMMAND_AUDIT_UNAVAILABLE` |
| Redis CONFIG SET | R437 | `REDIS_RESP_CONFIG_SET_UNAVAILABLE` |
| rclone exfiltration | R508 | `RCLONE_PROCESS_USERAGENT_AND_EGRESS_PROVENANCE_UNAVAILABLE` |
| cloudflared tunnel | R516 | `CLOUDFLARED_TUNNEL_SESSION_PROVENANCE_UNAVAILABLE` |

These remain explicit coverage gaps until their trusted producer contracts are
implemented and independently validated.

## Parser-backed supported replays

### R356 — Jenkins crumb issuer enumeration

The old fixture supplied HTTP-looking JSON fields but did not represent the
typed transport/application state produced by live parsing. It now supplies a
synthetic raw HTTP request and declares the corresponding TCP/HTTP record shape.
The benchmark parses the request with `HttpLight` before rule evaluation.

### R485 — BACnet WriteProperty request

The old fixture used free-text `Info` to claim a BACnet WriteProperty request.
That is no longer accepted by the rule. The fixture now carries a bounded
synthetic BACnet/IP UDP payload. The benchmark runs the same
`BacnetWritePropertyInspector` used by capture before setting the internal
capture-only provenance flag.

### R437 — Redis CONFIG SET

R437 remains producer-limited, but its replay now contains a bounded synthetic
RESP2 CONFIG SET request. The benchmark runs `Resp2CommandInspector`, the same
bounded parser used by capture, to derive the request-only capture flag. The
rule must still fail closed because request shape alone does not authenticate
the Redis server, authorization, correlated trusted audit, or abuse outcome.

## Metric interpretation

The benchmark reports:

- supported-detector recognition over supported malicious fixtures;
- alert-level precision/recall over supported malicious plus benign fixtures;
- unsupported trusted-producer scenarios separately;
- policy Shadow/Disabled decisions separately from detector misses.

A high detector-recognition rate does not imply high alert recall, and a
Shadowed match is not counted as an alert.
