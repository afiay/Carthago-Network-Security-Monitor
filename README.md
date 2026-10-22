# Carthago

A Windows desktop network-analytics and detection tool with live packet capture, rule‑based detection, and multi‑sink forwarding (OTLP, Azure, Splunk HEC, Elastic, Kafka, Webhook, CEF over Syslog). It includes a WPF UI for dashboards, alerts, analytics, integrations, and per‑sink delivery telemetry. fileciteturn2file3 fileciteturn2file5

---

## Table of Contents

1. [Key Features](#key-features)  
2. [Architecture](#architecture)  
3. [Core Components](#core-components)  
4. [Detections (Rule Engine)](#detections-rule-engine)  
5. [Data Flow](#data-flow)  
6. [UI Overview](#ui-overview)  
7. [Integrations & Sinks](#integrations--sinks)  
8. [Configuration](#configuration)  
9. [Build & Run](#build--run)  
10. [Performance Tuning](#performance-tuning)  
11. [Security Notes](#security-notes)  
12. [Extensibility Guides](#extensibility-guides)  
13. [Troubleshooting](#troubleshooting)  
14. [FAQ](#faq)  

---

## Key Features

- **Live capture & enrichment**: Parses L3/L4 and selected L7 (HTTP headers, TLS ClientHello incl. SNI/ALPN/JA3, QUIC long header, DNS Q/R). Enriches with WHOIS (RDAP), AbuseIPDB reputation, and (placeholder) VPN/Proxy heuristics. fileciteturn4file2 fileciteturn4file8 fileciteturn4file9 fileciteturn4file7  
- **Rule‑based detection**: 22 rules covering scans, floods/DoS, brute force, DNS anomalies/tunneling, beaconing (std‑dev & autocorr), exfiltration, VPN/Proxy, GeoIP blacklist, DHCP abuse, TLS issues, uncommon ports, cleartext creds, rep‑based alerts, plus Host Sweep, HTTP IP/no Host, URI anomaly, SMTP egress:25, ICMP tunneling, NXDOMAIN spikes. fileciteturn3file2  
- **Configurable sensitivity & hot‑reload**: Central `Sensitivity` scaling and `rules.json` overrides with FS watchers for debounce/hot reload. fileciteturn3file4 fileciteturn3file0  
- **Multi‑sink forwarding**: OTLP, Azure Monitor (DCE/DCR), Splunk HEC, Elastic Bulk, Kafka, CEF over (TLS)Syslog, generic Webhook; robust fan‑out manager with bounded queues, micro‑batching, retries/backoff, circuit‑breaking, per‑attempt timeouts, and delivery telemetry. fileciteturn0file1 fileciteturn0file5 fileciteturn0file4 fileciteturn0file7 fileciteturn0file0 fileciteturn0file6 fileciteturn1file0 fileciteturn0file3  
- **WPF UX**: Dashboard, Live Traffic, Alerts, Analytics, Settings, Integrations; ScottPlot‑based charts, rolling KPIs, detail dialogs, context menus, and a dedicated Sink Events monitor. fileciteturn2file0 fileciteturn2file4 fileciteturn2file5 fileciteturn1file4 fileciteturn1file8

---

## Architecture

```text
                   ┌─────────────────────────────┐
                   │          WPF UI             │
                   │  MainWindow + Pages         │
                   │  (Dashboard/Live/Alerts/    │
                   │   Analytics/Settings/       │
                   │   Integrations/SinkEvents)  │
                   └─────────────┬───────────────┘
                                 │ UI events & bindings
                                 ▼
        ┌────────────────────────────────────────────────────┐
        │           TrafficCaptureService                    │
        │  capture → parse → enrich (WHOIS, rep) → evaluate │
        └─────────────┬───────────────────────┬──────────────┘
                      │                       │
                      │ DetectionEvents       │ TrafficRecords
                      ▼                       ▼
             ┌─────────────┐           ┌─────────────┐
             │ SinkManager │           │  UI Streams │
             │ fan‑out     │           │ (tables/    │
             │ queues/retry│           │  plots/KPIs)│
             └──────┬──────┘           └─────────────┘
                    │
  ┌─────────────────┼──────────────────────────────────────────────────┐
  │                 │                 │                │               │
  ▼                 ▼                 ▼                ▼               ▼
 OTLP            Azure            Splunk HEC        Elastic         Kafka
  │               │                 │                │               │
  ▼               ▼                 ▼                ▼               ▼
 CEF/TLS Syslog   Webhook (JSON)    … (easily add more sinks)      
```
fileciteturn4file6 fileciteturn0file3 fileciteturn2file5

---

## Core Components

### Application Bootstrap
- **App.xaml.cs**: Loads `.env` (AbuseIPDB key), starts threat‑intel refresh; global unhandled exception handler. fileciteturn5file2  
- **PreferencesService**: versioned `AppPreferences` with atomic save/hot‑reload; raises change events (incl. Sensitivity). fileciteturn4file4 fileciteturn3file6

### Capture & Enrichment
- **TrafficCaptureService**: orchestrates capture → enrichment → rule evaluation; batches UI updates under pressure. fileciteturn4file6  
- **PacketHandler**: fast parse for IPv4/IPv6/TCP/UDP + selected L7 (HTTP/TLS/QUIC/DNS). fileciteturn4file2  
- **WhoisResolver** (RDAP), **AbuseIpdbClient**, **VpnProxyResolver** (stub). fileciteturn4file8 fileciteturn4file9 fileciteturn4file7  
- **WindowsProcessResolver**: best‑effort mapping of local ports to owning process (v4/v6 TCP/UDP) with optional Authenticode check. fileciteturn5file0

### Rule Engine
- **RuleEngine.Core/Detectors**: Evaluates `TrafficRecord` against enabled rules with cooldown suppression, correlation window, and periodic state cleanup. fileciteturn3file1 fileciteturn3file2  
- **Sensitivity**: central scaling knobs & thresholds used by detectors and UI. fileciteturn3file4  
- **rules.json**: default detector toggles & thresholds (override at runtime; hot‑reload). fileciteturn5file3

### Sinks & Fan‑out
- **SinkManager**: bounded per‑sink queues, retries (exponential backoff), per‑attempt timeouts, micro‑batching, circuit breaker, and delivery events. fileciteturn0file3  
- **Sinks**: OTLP, Azure Logs Ingestion, Splunk HEC, Elastic Bulk, Kafka, CEF/TLS Syslog, Webhook. fileciteturn0file1 fileciteturn0file5 fileciteturn0file4 fileciteturn0file7 fileciteturn0file0 fileciteturn0file6 fileciteturn1file0  
- **SinkHost**: constructs sinks from `AppPreferences`, wires events, supports reload. fileciteturn0file2

### UI Layer
- **MainWindow** (+ partials) and Pages: grids + plots + dialogs; UtcToLocal value converter. fileciteturn2file3 fileciteturn2file0 fileciteturn5file4  
- **SinkEventsPage**: live table of per‑sink success/failure with pause/clear. fileciteturn2file5  
- **IntegrationsPage**: edit all sink settings, save & hot‑reload sinks. fileciteturn1file7

---

## Detections (Rule Engine)

**Coverage summary** (IDs R001–R022):  
- **Scanning & Flooding**: Port scan, SYN/ACK ratio flood, host sweep. fileciteturn3file2 fileciteturn5file3  
- **Auth/Brute**: Repeated failed auth patterns. fileciteturn3file2  
- **DNS**: Volume spikes, entropy/label length, tunneling heuristics, NXDOMAIN spikes. fileciteturn3file2 fileciteturn5file3  
- **Beaconing**: Low‑jitter interval or autocorrelation hits with min samples and observation window. fileciteturn3file2  
- **Exfiltration**: Byte‑volume thresholds within sliding windows. fileciteturn3file2  
- **Geo/VPN**: Country blacklist and VPN/Proxy indicator. fileciteturn3file2  
- **L7 Anomalies**: HTTP IP/no Host, suspicious URI (length/entropy/b64‑like), SMTP egress on 25, ICMP tunneling. fileciteturn3file2 fileciteturn5file3  
- **TLS/Ports/Creds**: Weak TLS evidence, uncommon ports, cleartext credential hints. fileciteturn3file2  
- **Reputation/Feeds**: AbuseIPDB thresholding and URLHaus host feed. fileciteturn4file5 fileciteturn4file9

Tuning knobs live in `rules.json`; the engine hot‑reloads these at runtime. fileciteturn3file0 fileciteturn5file3

---

## Data Flow

1. **Capture** via `TrafficCaptureService`.  
2. **Parse** packet → `TrafficRecord` (adds process, service names, etc.). fileciteturn4file2 fileciteturn5file0 fileciteturn4file3  
3. **Enrich** WHOIS (RDAP), reputation, VPN/proxy hints. fileciteturn4file8 fileciteturn4file9 fileciteturn4file7  
4. **Evaluate** rules → zero or more `DetectionEvent`s. fileciteturn3file1  
5. **Publish to UI** (tables/plots/KPIs) and **fan‑out to sinks** via `SinkManager`. fileciteturn2file0 fileciteturn0file3

---

## UI Overview

- **Dashboard**: KPIs (PPS, throughput, active hosts/conns), sparklines + mean lines. fileciteturn2file0  
- **Live Traffic**: Rolling table (≈200) with filters (search/src/dst/proto/port/malicious). Double‑click opens detail dialog (overview, endpoints, WHOIS, reputation, HTTP/TLS/DNS, raw). Context menu supports blacklisting. fileciteturn1file3 fileciteturn1file4 fileciteturn1file8  
- **Alerts**: Rolling table (≈500) with filter predicate over common alert fields; copy‑summary action. fileciteturn1file3 fileciteturn1file8  
- **Analytics**: PPS over time with MA overlay, protocol distribution, top talkers, severity donut. fileciteturn2file0  
- **Integrations**: Configure sinks; `Save` persists and reloads sinks. fileciteturn1file7  
- **Sink Events**: Per‑sink success/failure stream with Pause/Clear. fileciteturn2file5

---

## Integrations & Sinks

Each sink implements `IDetectionSink.EmitAsync(DetectionEvent, ct)`. The `SinkManager` fans out with resilience. fileciteturn0file8 fileciteturn0file3

- **OTLP Logs**: sends via `OpenTelemetry.Logs` OTLP exporter to configured endpoint. fileciteturn0file1  
- **Azure Monitor (DCR/DCE)**: `LogsIngestionClient.UploadAsync` with table & stream details from preferences. fileciteturn0file5  
- **Splunk HEC**: POST to `/event` with token header. fileciteturn0file4  
- **Elastic**: Bulk NDJSON `_bulk` API (index, action metadata + source per event). fileciteturn0file7  
- **Kafka**: keyed by `SourceIp` to preserve per‑source ordering. fileciteturn0file0  
- **CEF over (TLS)Syslog**: TCP+TLS client; note: current TLS client callback accepts any certificate. **Harden before prod.** fileciteturn0file6  
- **Webhook**: JSON POST to arbitrary endpoint. fileciteturn1file0

**Delivery Telemetry**: `SinkHost` raises `SinkEmitted`/`SinkFailed`; `SinkEventsPage` displays rolling history. fileciteturn0file2 fileciteturn2file5

---

## Configuration

### Files & Environment
- **`.env`**: set `ABUSEIPDB_API_KEY` (do _not_ commit secrets). Loaded on startup. fileciteturn5file2 fileciteturn5file1  
- **`rules.json`**: enable/disable detectors and adjust thresholds. Hot‑reloaded. fileciteturn3file0 fileciteturn5file3  
- **`AppPreferences`**: app‑wide settings incl. sensitivity and all sink configs; persisted via `PreferencesService`. fileciteturn3file6 fileciteturn4file4

### Sensitivity
Global knob that scales thresholds and UI defaults; can be overridden via CLI/ENV (see `PreferencesService`). fileciteturn3file4 fileciteturn4file4

### Blacklist
Session‑scoped IP/CIDR blocks with expirations; used by context menus and evaluation shortcuts. fileciteturn4file0

### Threat Intelligence
URLHaus feed fetched hourly and cached under `Data/ThreatIntel`. fileciteturn4file5

---

## Build & Run

### Prerequisites
- Windows 10/11, .NET 8 SDK, admin rights for packet capture (depending on capture backend).  
- WPF desktop environment (project `Carthago.csproj`). fileciteturn2file3

### Steps
1. **Clone** and open in Visual Studio or `dotnet` CLI.  
2. **Configure**:
   - Create a `.env` next to the executable (or solution root):  
     ```ini
     ABUSEIPDB_API_KEY=your_key_here
     ```
     fileciteturn5file2
   - (Optional) Edit `rules.json` for detector tuning. fileciteturn5file3
   - Use **Integrations** page to configure sinks at runtime; settings persist. fileciteturn1file7
3. **Build**: `dotnet build` (Debug/Release).  
4. **Run**: `dotnet run` or start from Visual Studio; select a network adapter in the UI and press **Start**. fileciteturn2file3

---

## Performance Tuning

- **UI backpressure**: `TrafficCaptureService` batches UI updates and trims rolling buffers to avoid UI stalls under high PPS. fileciteturn4file6  
- **Process resolution cache**: `WindowsProcessResolver` caches per‑(proto,port,addr) to avoid table scans. fileciteturn5file0  
- **Sink fan‑out**: bounded queues + micro‑batching; tune batch sizes/timeouts in `SinkManager`. fileciteturn0file3  
- **Port service names**: background‑refreshed IANA map with fast in‑memory lookups. fileciteturn4file3

---

## Security Notes

- **Certificates in CEF sink**: TLS callback currently accepts any server certificate for convenience. Replace with proper validation before production. fileciteturn0file6  
- **Secrets**: keep `.env` out of source control; the app warns if `ABUSEIPDB_API_KEY` is missing and disables reputation lookups. fileciteturn5file2  
- **Blacklist persistence**: current blacklist is in‑memory; persistence requires a small extension in `BlacklistService`. fileciteturn4file0

---

## Extensibility Guides

### Add a New Sink
1. Implement `IDetectionSink` (and optionally `IBatchableSink`). fileciteturn0file8 fileciteturn0file3  
2. Register it in `SinkHost` based on `AppPreferences`. fileciteturn0file2 fileciteturn3file6  
3. Add config fields to `AppPreferences` + bind to `IntegrationsPage` for UI editing. fileciteturn3file6 fileciteturn1file7

### Add a New Detector
1. Add a detector in `RuleEngine.Detectors` and a toggle/threshold in `rules.json`. fileciteturn3file2 fileciteturn5file3  
2. Wire into `RuleEngine.Evaluate()` and consider state windows/cooldowns as appropriate. fileciteturn3file1  
3. If you need new fields, extend `TrafficRecord` and surface them in parsing/enrichment. fileciteturn3file5 fileciteturn4file2

---

## Troubleshooting

- **No reputation data**: Ensure `ABUSEIPDB_API_KEY` is present in `.env` (app warns at startup). fileciteturn5file2  
- **Integrations not delivering**: Check **Sink Events** page for failures and messages; verify endpoint URLs/tokens. fileciteturn2file5  
- **High CPU**: Disable Authenticode checks in `WindowsProcessResolver` (default is off) and consider lowering UI rolling windows. fileciteturn5file0 fileciteturn2file0  
- **Rules not applying**: Confirm `rules.json` path and that file watcher detected changes (hot‑reload). fileciteturn3file0

---

## FAQ

**Q: Where are sink settings stored?**  
In `AppPreferences` persisted via `PreferencesService`; edited in the **Integrations** UI. fileciteturn4file4 fileciteturn1file7

**Q: Can I correlate alerts by process?**  
Process resolution is best‑effort via port ownership and cached lookups; accuracy varies with NAT/ephemeral usage. fileciteturn5file0

**Q: Can I export alerts to my SIEM?**  
Yes—enable one or more sinks (Splunk/Elastic/OTLP/Azure/Kafka/CEF/Webhook). fileciteturn0file4 fileciteturn0file7 fileciteturn0file1 fileciteturn0file5 fileciteturn0file0 fileciteturn0file6 fileciteturn1file0

---

## License

SPDX-License-Identifier: MIT (confirm in your repository root as needed).

