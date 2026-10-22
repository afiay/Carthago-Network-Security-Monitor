# IoT Home / Small Office Pack

## Purpose

`carthago.iot-home.v1` adds optional IoT detections for camera or NVR beaconing, printer admin exposure, UPnP abuse, MQTT topic misuse, default credential attempts, discovery storms, and unauthorized external device control.

## Rule list

- `IOT001-IOT040`
- Coverage themes: MQTT enumeration and retained topics, Telnet or FTP default credentials, printer and JetDirect exposure, RTSP and ONVIF misuse, UPnP and SSDP storms, DHCP or ARP instability, and remote support anomalies.

## Default modes by profile

- `IoTHeavy`: `Alert`
- `HomeLab`: `Shadow`
- `SmallBusiness`: `Shadow`
- `Research`: `Alert`

## Telemetry requirements

- MQTT and IoT protocol metadata
- Camera and printer inventory
- Local discovery visibility

## Tuning guidance

- Populate approved MQTT brokers and known device owners before enabling broader alerting.
- Keep consumer-cloud device traffic in `Shadow` until it is clearly separated from suspicious beaconing.
- Use discovery-storm hunts to identify noisy subnets before changing default modes.

## Approved asset config

- `Approved.MqttBrokers`
- Approved camera or NVR inventory
- Known remote-support tool allowlists

## Known false positives

- Approved MQTT brokers and smart-home hubs.
- Printer or camera vendor maintenance traffic.
- Legitimate network discovery during device onboarding or support.

## Replay benchmark summary

- Positive sample: `iot-default-credential-attempt`
- Benign sample: `normal-mqtt-approved-broker`
- Benchmark expectations: IoT-heavy positive pass rate at or above `70%` with zero critical benign spam.

## Response recommendations

- Review device ownership and destination legitimacy.
- Change default credentials only after owner approval.
- Preserve packet evidence before deciding on network containment.

## Safety notes

- Fragile consumer devices are never blindly auto-blocked.
- Credential changes require owner coordination.
- Journaled detections remain authoritative even if the pack is disabled or removed.

## References

- MITRE ATT&CK discovery tactic
- CISA small and home office network security guidance
- Sigma IoT detection guidance
