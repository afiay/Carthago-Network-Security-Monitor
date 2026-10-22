# OT / Industrial Pack

## Purpose

`carthago.ot-industrial.v1` adds optional OT and ICS detections for Modbus writes, BACnet WriteProperty, Siemens S7 anomalies, DNP3 control operations, IEC-104 control behavior, OPC UA browse or write misuse, engineering workstation abuse, and IT to OT boundary violations.

## Rule list

- `OT001-OT050`
- Coverage themes: OT protocols outside approved segments, Modbus and BACnet writes, S7 control commands, DNP3 and IEC-104 control functions, OPC UA browse or write bursts, engineering workstation misuse, and historian or controller egress.

## Default modes by profile

- `OTSegment`: `Alert` when approved OT segments are configured.
- `Enterprise`: `Shadow`
- `HomeLab`: `Disabled`
- `Research`: `Alert`

## Telemetry requirements

- OT or ICS protocol metadata
- Approved OT segments
- Engineering workstation inventory

## Tuning guidance

- Populate `Approved.OtSegments` before promoting the pack into paging mode.
- Keep controller write operations behind conservative alert thresholds until site baselines are validated.
- Use replay and hunt output to separate operational maintenance from unsafe control activity.

## Approved asset config

- `Approved.OtSegments`
- Approved controller or engineering workstation inventories

## Known false positives

- Planned maintenance windows with authorized control writes.
- Approved engineering workstation activity.
- Historian or controller read-only monitoring traffic.

## Replay benchmark summary

- Positive sample: `modbus-write-function`
- Benign sample: `normal-ot-approved-modbus-read`
- Benchmark expectations: OT segment positive pass rate at or above `75%` with zero critical benign spam.

## Response recommendations

- Notify the OT engineer or system owner.
- Collect packet evidence and control-system context.
- Explicitly remind responders not to auto-block controller traffic.

## Safety notes

- Do not auto-block controller or field-device traffic.
- Validate any action with OT engineering before containment.
- The local detection journal remains authoritative and durable for OT evidence.

## References

- MITRE ATT&CK for ICS matrix
- CISA ICS defensible architecture guidance
- Sigma industrial protocol guidance
