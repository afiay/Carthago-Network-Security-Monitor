# CARTHAGO — R580–R584 cross-boundary request fanout

**Status:** SOURCE CANDIDATE — UNVERIFIED. Five authored rule predicates and
rule-specific xUnit cases; **0 tests executed**. No build, replay, capture,
benchmark, CI or holdout run. No production-validation claim.

**Branch:** feature/carthago-reliability-hardening
**Base HEAD:** a5dc99307dcd59fe38123c95d2f7aaa211c4bfbb
**Publication SHA:** to be assigned after an atomic expected-HEAD update.

## Rule matrix

| ID | Observed predicate and existing producer | Default | Scope, limitations and realistic benign cases |
| --- | --- | --- | --- |
| R580 | Public client sends parsed RESP2 CONFIG SET **requests** to three distinct RFC1918 /24s in five minutes; PacketHandler Redis flag. | DatabaseServiceExposure; High, Candidate/Shadow, confidence floor 86%, threshold 3, window 300 s, cooldown 600 s. | Request only; no authenticated identity, reply or config change established. Authorized external administration/scanning or NAT may resemble this. |
| R581 | RFC1918 client sends RESP2 CONFIG SET **requests** to three public /24s. | DatabaseServiceExposure; High, Candidate/Shadow, 86%, 3 / 300 s / 600 s. | Legitimate cloud Redis administration possible; no server outcome established. |
| R582 | RFC1918 client sends parser-confirmed known-default HTTP Basic credentials to admin paths in three public /24s. | IdentityAccess; High, Candidate/Shadow, 88%, 3 / 300 s / 600 s. | No accepted login, device identity or compromise; approved remote management may look similar. |
| R583 | RFC1918 source sends BACnet Who-Is discovery requests to three public /24 networks via UDP/47808. | IotOtAdvanced; High, Candidate/Shadow, 82%, 3 / 300 s / 600 s. | No device reply or ownership established; BBMD or foreign-device routing may be authorized; UDP spoofing remains possible. |
| R584 | RFC1918 source sends bounded SMB2 WRITE **request shapes** to three public /24 networks via TCP/445. | ExfiltrationAdvanced; High, Candidate/Shadow, 88%, 3 / 300 s / 600 s. | No file-write result or exfiltration established; approved SMB backup services may resemble this. |

## Distinctness from the live registry

- R580 is request-only fanout to three private /24s, unlike R564's
  wire-correlated Redis +OK response threshold and R561's single-host errors.
- R581 changes the Redis direction to private-to-public with independent
  three-public-/24 correlation.
- R582 is outbound public-target default Basic activity; R549 covers private
  cross-subnet default Basic attempts.
- R583 is outbound Who-Is to public networks; R547 covers inbound discovery.
- R584 is outbound SMB2 WRITE to public networks; R556 covers inbound WRITE.

These are five distinct network-boundary predicates, not five names for a
single successful attack. They use existing capture producer fields in the
current RuleRegistry, not a separate protocol catalog or new sensor.

## Producer and evidence safeguards

- Parser or bounded classifier evidence is mandatory: Redis request flag with
  RESP2 metadata, HTTP default-Basic flag plus redacted Authorization and
  anchored admin route, BACnet Who-Is operation, or SMB2 WRITE request shape.
- Source/destination IPv4 classes and /24 boundaries are checked with reserved,
  special-use, multicast and documentation-address exclusions.
- Coherent TCP/UDP flags, exact ports, bounded payload length, no incompatible
  TLS/QUIC/DNS/HTTP/Redis metadata, strict time order and unique packet IDs are
  required. Freeform Info and generic port numbers alone cannot qualify.
- Each rule holds a separate bounded correlation window: 1,024 sources,
  32 /24 targets and 128 packet IDs per source. Five-minute expiry, ten-minute
  cooldown, fresh three-target cycle and fail-closed saturation apply.
- Rule-specific structured evidence includes only fixed parser labels,
  directions, count, window and request-only/outcome-unknown status. No raw
  Authorization values, HTTP URLs, Redis arguments, SMB paths or payloads
  are added. Standard engine endpoint fields and existing journaling,
  persistence, privacy policy and suppressions remain unchanged.
- Approved administrator-source exclusions are applied to applicable
  Redis/default-Basic candidates. More specialized topology exemptions are
  still acceptance work; Shadow mode must not be silently promoted.

## Authored xUnit scenarios — zero executed

The R580R584AdvancedAccuracyBatchTests fixture has parameterized scenarios
for all five IDs: three distinct subnets, same-/24 repetition, mixed sources,
wrong direction, reserved addresses, duplicate IDs, out-of-order and expired
timestamps, Info-/port-only spoofing, malformed/contradictory metadata, and
fresh-subnet cooldown suppression. It also asserts unique registration,
Candidate/Shadow defaults and bounded existing BACnet, SMB2 and HTTP parser
classification.

Outstanding verification GAs: targeted plus full xUnit suite on the owner's
authorized Windows environment; per-ID real PacketHandler integration,
serialization/import and privacy, concurrency and approval exclusions;
benign replay/field controls and exact SHA/TRX evidence. Evidence reachability
remains **CONDITIONAL**, not validated or operational, until then.

Frozen V1 holdout, V2 provenance, the R102/R118/R163 confidence floors and
separate R275/R295/R343 quality tracks are untouched. The independent rule
automation should re-read live HEAD and reconcile IDs before its next write.
