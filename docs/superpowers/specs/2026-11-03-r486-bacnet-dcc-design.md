# GA — R486 BACnet DeviceCommunicationControl capture evidence design

## Intent

Enhance **existing R486**, not a new rule, by observing bounded BACnet/IP
unsegmented ConfirmedRequest service 17, specifically a device-communication
**disable** or **disable-initiation** request. R486 currently lacks trustworthy
operation evidence and must not match a port, label or replay description alone.

## Selected implementation

Reuse `PacketHandler`, `TrafficRecord`, `RulePrecisionCatalog`,
`OtIcsDeepPrecisionDetectionRuleBase` and the existing BACnet/IP capture route
added for R485. Add a narrow privacy-minimizing DCC wire-shape inspector,
capture-only flag, strict R486 evidence gate, synthetic test sources and the
existing developer ledger. Restrict observations to an externally crossing
UDP/47808 request with the BVLC *Original-Unicast* function, valid NPDU,
ConfirmedRequest APDU and mandatory `[1]` disable state (1 or 2).
Optionally accept `[0]` time duration
as 1–2 octets. A password-bearing DCC variant is **not** admitted in the first
iteration until the character-string encoding can be fully validated; record
that limitation rather than claiming complete coverage.

Accept only BACnet/IPv4 Annex J BVLC 0x81. BACnet/IPv6 Annex U uses a
different BVLC layout and is deliberately unsupported, so IPv6 datagrams
carrying 0x81 bytes must never be misattributed as valid BACnet/IP.
Reject incomplete IPv4 captures, IP fragments, malformed lengths,
unexpected/context tags, future extension fields, response PDUs, segmented
requests, BVLC Original-Broadcast function, enable state 0, absent destination, internal-only
requests and imported text/JSON provenance claims.
The BVLC function designates unicast framing; a directed-broadcast destination
cannot be reliably excluded without the interface's subnet configuration.
Do not claim independently verified transport unicast or source authorization.

No password, value, authenticated device identity, raw request bytes or
original packet text is retained. An observed DCC disable request is not proof
the controller accepted it or ceased communication.

**Shadow-only** output, including permissive user tuning, with existing
R486 confidence floor **86%**, threshold, window and cooldown unchanged.
Cooldown matches return `SuppressedMatch` before engine preparation.
Preserve frozen V1, pending V2, existing R102/R118/R163 floors, source
registries and all unrelated rules/automations.

## Approaches considered

1. **Selected:** connect a narrow DCC capture parser to existing R486, following
   the approved R485 pattern; accurate attribution and bounded cost.
2. Tune existing R486 text/port heuristics: rejected because a product string
   cannot establish a real DCC service request.
3. Create a separate protocol service or new rule ID: rejected because Carthago
   already has the rule and its detection engine.

## Verification status

`SOURCE CANDIDATE — UNVERIFIED`. Author real-world-shaped synthetic positive,
negative, privacy, import-spoof, cooldown, overlap and shadow-preservation tests,
but do **not execute** builds, tests, benchmarks, capture or holdouts until
the owner separately authorizes test time. An eventual green synthetic suite
does not prove field precision or device-write/disable success.

References: [ASHRAE BACnet Addendum](https://bacnet.org/wp-content/uploads/sites/4/2022/08/Add-2001-135a.pdf),
[BACnet International encoding](https://bacnet.org/wp-content/uploads/sites/4/2022/08/Encoding.pdf).
