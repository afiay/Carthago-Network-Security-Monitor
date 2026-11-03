# R286 / R485 evidence-producer enhancement — approved design

## Intent

Improve two existing, currently fail-closed detection rules through validated live-capture evidence rather than adding new rule IDs or trusting descriptive `Info` text. R286 observes a plaintext LDAPv3 simple BindRequest; R485 observes a BACnet/IPv4 confirmed WriteProperty request. Neither observation asserts an authentication success or a completed property change.

## Scope and constraints

- Reuse `LdapMessageInspector`, `OtProtocolLight`, `PacketHandler`, `TrafficRecord`, existing rule/precision profiles and approved-asset policies. Do not create another detection engine.
- Extend strict, bounded capture-byte inspection with client-to-server direction, protocol-specific framing, and privacy-minimized capture-only flags. No raw passwords, DNs, BACnet property values or payloads in telemetry.
- Reject malformed, truncated, fragmented, ambiguous, wrong-direction, TLS/LDAPS, SASL/anonymous LDAP and segmented BACnet operations. Existing start-of-flow / no-reassembly limitations must fail closed.
- The captured IP length and the inspected TCP first-payload length must both be complete; a 4 KiB inspection-budget clip must never attest an LDAP operation. BACnet/IP requests may legitimately originate on UDP/47808 and target UDP/47808, so APDU type—not source-port exclusion—defines request shape. The first BACnet scalar value subset is unsigned/signed integer, REAL and enumerated only.
- R286 matches only a verified nonempty simple authentication field in a cleartext BindRequest across an internal/external boundary; R485 matches only a verified complete unsegmented confirmed WriteProperty request across an internal/external boundary. Existing approved management/OT traffic stays Shadow.
- New evidence may produce only **Shadow-suppressed candidate observations** pending independent original-source accuracy review. Preserve the historically asserted profile metadata (including the pre-existing `DefaultMode=Alert` profiles), but forcibly mark newly matched R286/R485 events `Shadowed` before handing them to the engine. Do not enable actual Alert delivery, change rule confidence floors, relabel known missed positives, or alter Holdout V1/V2.
- On duplicate/cooldown, return `RuleEvaluationResult.SuppressedMatch` with no emitted event: the engine clears a plain `Suppressed` event status during preparation, so a cooldown must not depend on an event carrying that state.
- Preserve R286 minimum confidence 78% and R485 minimum confidence 86%; keep original rule IDs, registry entries, thresholds/cooldowns and user tuning.
- Tests must be **authored but not run** until the owner separately says it is test time. No builds, replays, live capture, or holdout execution in this development turn. All new work is **SOURCE CANDIDATE — UNVERIFIED**.

## Approaches

1. **Selected: evidence-first producer integration.** Validate wire requests in the existing capture path and let the two existing rule classes consume those flags. More implementation work, but prevents synthetic labels and text descriptions from masquerading as packets.
2. Precision-only threshold tuning: smaller change but cannot improve rules whose trusted operation evidence is absent.
3. Separate protocol service: broader and duplicative; rejected because it would bypass the existing engine and increase runtime overhead.

## Review and readiness

Synthetic positive, negative, malformed, spoofed record, process direction, policy, and privacy test sources must be present. Reaching green xUnit in a future authorized run will validate implementation contracts, not original-source precision or operational alert eligibility. R286/R485 stay Shadow pending source review.

Technical references: RFC 4511 (https://datatracker.ietf.org/doc/rfc4511/) and BACnet International wire encoding examples (https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf).
