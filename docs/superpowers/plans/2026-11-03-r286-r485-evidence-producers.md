# R286 / R485 evidence-producer enhancement implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Owner expressly prohibits execution of tests until separate test-time authorization.

**Goal:** Enable strictly attributed Shadow candidate detection observations for existing R286 and R485 without trusting descriptive packet metadata.

**Architecture:** Reuse bounded packet decoders and live `PacketHandler`. Add capture-only flags on `TrafficRecord`, then let the existing rule classes require the verified flags and their existing boundary/approved-asset controls. Do not create new rule IDs or a second engine.

**Tech Stack:** C#, .NET, xUnit, `ReadOnlySpan<byte>`, existing `PacketHandler` and precision-rule abstractions.

**Spec:** `docs/superpowers/specs/2026-11-03-r286-r485-evidence-producers-design.md`

## Global constraints

- Work on `feature/carthago-reliability-hardening` only; no new branch or automatic Alert promotion.
- R286 minimum confidence 78%, R485 86%; R102/R118/R163 floors 80%/86%/84% unchanged. Preserve their existing profile default Alert metadata for regression compatibility but force every new event's suppression status to Shadowed.
- Immutable Holdout V1 and pending V2; no replay relabeling, private evidence or payload retention.
- Tests are written before product changes but cannot be executed during this turn by explicit owner restriction. Consequently no RED/GREEN/TDD completion claim.
- Use existing bounded, capture-only, internal-setter telemetry semantics. Every malformed or ambiguous input fails closed.

## Review focus

1. A truncated LDAP BindRequest must not be admitted; add parser and packet integration negatives.
2. An anonymous or SASL BindRequest must not be misclassified as a nonempty cleartext simple bind; add negative fixtures.
3. BACnet WritePropertyMultiple/ReadProperty, segmented confirmed requests and BVLC length mismatch must not become R485; add negatives.
4. A forged imported `TrafficRecord.Info` or JSON flag must not produce rule matches; add rule tests.
5. Approved BACnet maintenance and a missing internal/external boundary must remain non-alerting; add rule tests.

---

### Task 1: Extend LDAP operation inspection

**Files:** Modify `Carthago/Services/ProtocolIntelligence/LdapMessageInspector.cs`, `Carthago.Tests/ProtocolIntelligence/LdapMessageInspectorTests.cs`.

**Interface:** `TryInspectSimpleBind(ReadOnlySpan<byte> bytes, bool verifiedPlaintextMessageBoundary, out LdapSimpleBindObservation observation)`; observation contains only `MessageId`, `BytesConsumed` and `HasNonEmptyCredential`.

- [ ] Author positive nonempty simple-bind, anonymous, SASL, invalid LDAP version, truncated, malformed BER, unknown controls and duplicate/coalesced negatives.
- [ ] Extend existing bounded BER TLV inspection; no string decoding, credential copying or payload retention.
- [ ] Record `SOURCE CANDIDATE — UNVERIFIED`; execution deferred until explicit owner test time.

### Task 2: Integrate R286 into existing flow and engine

**Files:** Modify `Carthago/Models/TrafficRecord.cs`, `Carthago/Services/PacketHandler.cs`, `Carthago/Engine/Rules/Expansion/R286_LDAPSimpleBindOverCleartextExternalRule.cs`; test `Carthago.Tests/LdapSimpleBindCaptureIntegrationTests.cs`.

**Interface:** Internal-setter `LdapCleartextSimpleBindObserved` on `TrafficRecord`; only `PacketHandler` populates it after a verified first client TCP payload to port 389 and no TLS. R286 consumes this flag, ensures cross-boundary and returns Shadow candidate evidence through the existing rule match path.

- [ ] Author raw-packet positive, missing SYN, wrong direction/port, TLS, fragmented, imported spoof, missing boundary and duplicate/cooldown tests.
- [ ] Wire captured-span admission and privacy-safe flag; avoid late protocol interpretation overwrites.
- [ ] Replace R286 unconditional `NoMatch` only for exact flag and policy; preserve original profile and force every newly emitted event to Shadowed.
- [ ] Record `SOURCE CANDIDATE — UNVERIFIED` without executing tests.

### Task 3: Add a bounded BACnet confirmed WriteProperty inspector

**Files:** Create `Carthago/Services/ProtocolIntelligence/BacnetWritePropertyInspector.cs`, `Carthago.Tests/ProtocolIntelligence/BacnetWritePropertyInspectorTests.cs`.

**Interface:** `TryInspect(ReadOnlySpan<byte> datagram, bool verifiedCompletePlaintextUdpDatagram, out BacnetWritePropertyObservation observation)`; metadata is service kind/invoke ID and structural target presence, no object/property values.

- [ ] Author positive BVLC/NPDU/APDU fixtures and negative ReadProperty, WritePropertyMultiple, segmented, wrong-direction, malformed length, forwarded-ambiguous and truncation fixtures.
- [ ] Implement bounded BACnet/IP BVLC/NPDU/unsegmented confirmed request with service choice 0x0F and structurally validated object/property target.
- [ ] Record `SOURCE CANDIDATE — UNVERIFIED` without executing tests.

### Task 4: Integrate R485 into existing flow and engine

**Files:** Modify `Carthago/Models/TrafficRecord.cs`, `Carthago/Services/PacketHandler.cs`, `Carthago/Engine/Rules/Expansion/R485_BACnetWritePropertyRequestRule.cs`, `Carthago.Tests/BacnetWritePrecisionTests.cs`, `Carthago.Tests/NetworkBatch481490AccuracyTests.cs` (only if a current assertion requires adjustment).

**Interface:** Internal-setter `BacnetWritePropertyRequestObserved` on `TrafficRecord`; `PacketHandler` populates it only for a verified complete UDP request to port 47808. Existing R485 requires capture flag, cross-boundary and approved-asset checks, and produces Shadow candidate event; no successful write claim.

- [ ] Author direct packet and rule positive, benign maintenance, wrong direction, malformed, imported spoof, cooldown, privacy, and duplicate-controller tests.
- [ ] Wire inspector to packet path and update R485 to consume trusted flag, preserving original profile, confidence 86, threshold/cooldown and forced event Shadow status.
- [ ] Update `docs/DEVELOPMENT_VALIDATION_LEDGER.md` and preserve original benchmark/holdout evidence.
- [ ] Record `SOURCE CANDIDATE — UNVERIFIED` and owner-only future Release/xUnit commands. Do not run them.
