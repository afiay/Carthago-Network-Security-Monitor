# R236–R240 — typed IoT HTTP/MQTT and Modbus write precision

**CANDIDATE — UNVERIFIED.** Authored 2026-10-28 on the existing `feature/carthago-reliability-hardening` branch. **52 advanced rule xUnit facts plus 4 new Modbus parser facts authored; zero executed.** No build, test, replay, holdout, CI or runner was launched. No frozen or synthetic replay labels were changed.

## Actual changed paths

Production: `Carthago/Engine/Rules/Expansion/R236_IotFirmwareUpdateOverCleartextRule.cs`, `R237_IotDefaultWebAdminAccessRule.cs`, `R238_SmartHomeHubCloudBurstRule.cs`, `R239_Zigbee2MqttBridgeInternetAccessRule.cs`, `R240_ModbusWriteFunctionRule.cs`, `NetworkBatch236240Evidence.cs`; `Carthago/Engine/Rules/IotOt/IotOtPrecisionDetectionRuleBase.cs`; `Carthago/Services/OtProtocolLight.cs`.

Tests: `Carthago.Tests/NetworkBatch236240Context.cs`, `R236AdvancedAccuracyBatchTests.cs` (10), `R237AdvancedAccuracyBatchTests.cs` (10), `R238AdvancedAccuracyBatchTests.cs` (12), `R239AdvancedAccuracyBatchTests.cs` (10), `R240AdvancedAccuracyBatchTests.cs` (10), plus 4 added facts in `Carthago.Tests/OtProtocolLightTests.cs`. All unexecuted.

## Observable contracts and authored scenarios

- **R236:** Requires parsed cleartext TCP HTTP GET, anchored firmware/update/OTA artifact route and independently attributed device-updater process. A GET is a **request**, not proof of completed firmware transfer, installation, signature verification or tampering. Cases: typed positive, unrelated binary, Info spoof, missing process, TLS contradiction, POST, query-only indicator, duplicate packet, query/Info privacy and Alert/84.
- **R237:** Requires parsed cleartext HTTP request, anchored appliance default route and independent device-updater process. Does **not** claim successful default credential authentication. Cases: typed positive, generic admin, Info/default-credential spoof, missing process, lookalike route, UDP contradiction, TLS contradiction, duplicate, privacy and Alert/82.
- **R238:** Requires private-source hub process plus typed vendor-cloud authority from TLS SNI or cleartext HTTP Host, external IP destination and 60 unique packet IDs in five minutes. Cases: 60-event positive, isolated heartbeat, Info spoof, missing process, host lookalike, internal destination, external source, TLS/HTTP contradiction, duplicate, independent sources, out-of-order and Shadow/72.
- **R239:** Requires attributed Zigbee2MQTT process, parsed MQTT CONNECT or parsed topic-observed PUBLISH on cleartext TCP/1883 and external IP broker. Topic classification is a boolean, **not** a retained raw topic. Cases: typed positive, local broker, Info spoof, generic MQTT process, unparsed publish, TLS, CONNECT, duplicate, secret privacy and Alert/84.
- **R240:** Requires TCP/502 client-to-server operation identified as `modbus.write` by bounded MBAP parser, not port, guessed ApplicationService or packet Info. Only function codes 5, 6, 15, 16 are classified as write; responses remain generic `modbus`. Cases: typed positive, read-only, Info spoof, port-only, response direction, TLS, UDP, duplicate, Info privacy and Alert/90. Four additional parser facts cover write request, write response, read, and unrecognized function.

The shared `NetworkBatch226230Evidence.Window` provides instance-owned, bounded, duplicate-resistant, monotonic packet observation; no global mutable counter was added. The IoT event privacy scope now includes R236–R240: host/destinationHost and raw Info are redacted; request paths and MQTT topics are not persisted. Existing confidence floors, modes, thresholds, asset approvals, baseline-readiness gates and frozen evidence are unchanged.

## Limitations and deferred verification

- Process attribution is an **unverified capture enrichment dependency**. Requiring exact device/hub/bridge process names deliberately sacrifices recall when enrichment is absent; an updater process alone does not prove device ownership or an approved asset.
- Cleartext HTTP parsing is bounded and first-packet oriented. HTTPS is not decrypted. TLS SNI is handshake metadata, not decrypted vendor-cloud application activity.
- MQTT parser covers bounded MQTT 3.1.1 first packets only, not stream reassembly or TLS; an external broker is not automatically unauthorized.
- Modbus parser identifies request function code and MBAP framing, not write success, authorized engineering context, PLC state changes or a complete Modbus PDU.
- Vendor host matching is exact-root/suffix, but DNS/host ownership and approved cloud destinations are not independently verified. Private/public address checks do not establish approved segmentation.
- `scripts/verify-all-rule-batches.ps1` remains the single deferred Windows verification entry point and was **not executed**. Static source inspection is not compilation or regression evidence.
- Frozen R102 V1 remains **FAILED 4/6**, immutable; V2 needs independent licensed PCAP and separate analyst approval. R102 80%, R118 86%, R163 84% floors preserved.

**Next consecutive five: R241–R245, followed by R246–R250.**
