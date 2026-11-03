# Research-backed detection rules R057-R122

This document explains the non-placeholder implementation strategy for the extended Carthago rules.

## Design decision

R057-R122 are concrete `TelemetryDetectionRuleBase` rules. Each rule has a real descriptor, is registered in `RuleRegistry`, and evaluates the current `TrafficRecord` through `ExtendedRuleDetectors`. A rule returns `NoMatch` when its required telemetry is absent. It does not emit demo-only, hardcoded, or synthetic events.

## Research basis used

The rules are grounded in common network-observable attacker behaviors:

- Asset and baseline novelty: new device, new MAC/IP relationship, first-time destination/ASN/country, and new internal service are passive-baseline rules.
- IPv6: Router Advertisement, Neighbor Discovery, transition tunnels, and multicast bursts follow common IPv6 control-plane and transition-mechanism observables.
- Lateral movement: RDP, SMB/admin shares, WinRM, WMI/DCOM, RPC service control, Kerberos, LDAP, NTLM, LLMNR, and NBNS rules use network footprints associated with remote services and lateral movement.
- Payload exploitation: JNDI/Log4Shell, SQL injection, traversal/LFI, webshell upload, deserialization, command injection, reverse shell, scanning user-agents, malware URI markers, and PowerShell download cradles use HTTP URI/header/info evidence.
- DNS: DGA-like domains, long labels, high entropy, fast-flux, dynamic DNS, CNAME chains, internal-name leakage, and beaconing use DNS qname/answer/TTL/timing evidence.
- Cloud/SaaS exfiltration: cloud upload, upload-after-sweep, split exfiltration, high upload ratio, Git raw access, chat API egress, paste/file-drop egress, and export-like paths use HTTP/TLS host, method, URI, destination, and byte counters.
- IoT/OT: MQTT, UPnP/SSDP, Telnet, default credentials, camera/NVR beaconing, Modbus, BACnet, CoAP, and Zigbee gateway rules use ports, protocol names, and packet info fields.

## Telemetry contract

The implementation uses only these existing fields from `TrafficRecord`:

- identity: `Source`, `Destination`, `MacSource`, `MacDestination`, `ProcessName`, `NetworkType`
- transport: `Protocol`, `SourcePort`, `DestinationPort`, `IpVersion`, `IcmpTypeCode`, `Length`, `L4Len`
- DNS: `DnsQname`, `DnsQtype`, `DnsRcode`, `DnsAnswers`, `DnsTtl`, `DnsIsResponse`
- HTTP: `HttpMethod`, `HttpHost`, `HttpUri`, `HttpUserAgent`, `HttpRequestHeaders`
- TLS/QUIC/SSH: `Sni`, `TlsSni`, `Alpn`, `TlsAlpn`, `Ja3`, `Ja4`, `Hassh`, `QuicAlpn`, `QuicConnectionIdHash`, certificate fields
- enrichment: `WhoisASN`, `WhoisCountry`, `WhoisOrganization`, `ReputationLastSeen`, reputation fields, GeoIP fields
- generic packet text: `Info`

## No fake-detection rule

When the exact enrichment does not exist, the rule does not fake telemetry. Examples:

- R099 only triggers if domain-age/recent-registration evidence appears in enrichment text or the reputation last-seen timestamp is fresh.
- R071 only triggers when the record or segment metadata explicitly says IPv4-only/no IPv6.
- OT rules such as R120/R121/R122 use actual protocol ports or protocol strings; they do not infer OT behavior from unrelated packets.

## Operational notes

These rules are enabled by default because they are concrete. If a deployment expects noisy protocols, disable or tune the specific rule in `rules.json` using the v2 structure:

```json
{
  "Version": 2,
  "Profile": "Balanced",
  "Rules": {
    "R071": { "Enabled": false },
    "R121": { "Enabled": false }
  }
}
```

The local detection journal remains authoritative. UI filters, incident grouping, exports, and sink failures must not erase emitted `DetectionEvent` objects.


## v4 durability and tuning additions

R057-R122 remain concrete telemetry rules. They now also support a safer common tuning path through `rules.json` for rules that use shared threshold/window semantics:

```json
{
  "Version": 2,
  "Rules": {
    "R102": {
      "Enabled": true,
      "Threshold": 50,
      "QueryLengthThreshold": 180,
      "EntropyThreshold": 3.5
    },
    "R115": {
      "Enabled": true,
      "Threshold": 60,
      "WindowSeconds": 60
    }
  }
}
```

The engine preserves unknown extension fields in the active parsed config object and exposes typed accessors for rule implementations:

- `RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max)`
- `RuleEngine.GetRuleDoubleSetting(ruleId, key, defaultValue, min, max)`
- `RuleEngine.GetRuleStringListSetting(ruleId, key)`

External sink delivery is deliberately not treated as the source of truth. When a sink fails, the detection remains in the mandatory local journal and a separate JSONL outbox spool is written under:

```text
%ProgramData%\Carthago\detections\outbox\sink-outbox-YYYY-MM-DD.jsonl
```

This gives operators a durable retry/audit queue without allowing Elastic, Splunk, webhooks, syslog, Kafka, or any other external destination to erase a local detection.


## Reference sources used for rule families

- MITRE ATT&CK T1071.004 DNS supports DNS tunneling/beaconing and DNS-based C2 reasoning used by R094-R103.
- MITRE ATT&CK T1021 and T1021.002 support lateral movement reasoning for remote services, SMB, admin shares, and related internal sweep rules used by R073-R083.
- OWASP SQL Injection and Path Traversal references support payload rules R085 and R086.
- CISA/NCSC Log4j guidance supports Log4Shell/JNDI pattern detection for R084.
- MQTT protocol documentation supports the IoT/MQTT family R113-R115.

URLs:
- https://attack.mitre.org/techniques/T1071/004/
- https://attack.mitre.org/techniques/T1021/
- https://attack.mitre.org/techniques/T1021/002/
- https://owasp.org/www-community/attacks/SQL_Injection
- https://owasp.org/www-community/attacks/Path_Traversal
- https://www.cisa.gov/news-events/news/apache-log4j-vulnerability-guidance
- https://mqtt.org/
