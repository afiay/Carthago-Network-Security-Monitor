// SPDX-License-Identifier: MIT
// File: Engine/RuleEngine.Detectors.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics.Metrics;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Services
{
    /// <summary>
    /// All rule detectors (R001–R039) and their per-rule state.
    /// Notes:
    /// - Depends on helpers in RuleEngine.Core.cs (NS, NP, SuppressRepeat, ShannonEntropy, AutocorrSpike, ExtractTlsFlag, BuildHints, IsPrivateIp, TrimAndCount).
    /// - Thresholds for R001–R022 are read from RuleEngine.Config.cs (_cfg.* with sane defaults). New rules (R023+) use local conservative thresholds to avoid touching config.
    /// - All per-rule state is bounded/cleaned opportunistically to prevent unbounded growth.
    /// - Wire-ups for new rules must be added in RuleEngine.Core.Evaluate(...).
    /// </summary>
    public static partial class RuleEngine
    {
        // ===== Detector state metrics (OpenTelemetry gauge) =====
        private static readonly Meter _detectorMeter =
            new("Carthago.RuleEngine.Detectors");

        // Single global gauge with approximate total in-memory entries across detectors.
        // If you want per-rule series later, add more measurements with a "rule" tag.
        private static readonly ObservableGauge<long> _detectorStateGauge =
            _detectorMeter.CreateObservableGauge(
                "carthago.detector_state_entries",
                ObserveDetectorStateEntries,
                unit: "entries",
                description: "Approximate total number of in-memory state entries used by detectors"
            );

        private static IEnumerable<Measurement<long>> ObserveDetectorStateEntries()
        {
            long total = 0;
            try
            {
                total += _srcDstToPorts.Count;
                total += _packetTimes.Count;
                total += _floodWindows.Count;
                total += _authAttempts.Count;
                total += _dnsQueries.Count;
                total += _beaconing.Count;
                total += _exfilBytes.Count;
                total += _arpTable.Count;
                total += _dhcpActivity.Count;
                total += _hostSweeps.Count;
                total += _icmpWindow.Count;
                total += _icmpBytes.Count;
                total += _icmpTimes.Count;
                total += _nxdomain.Count;
                total += _ja4Counts.Count;
                total += _sshFpCounts.Count;
                total += _adminSweeps.Count;
                total += _dnsTxtBySrc.Count;
                total += _pairBytes.Count;
                total += _sniJa4Drift.Count;
                total += _quicHiEntropyBySrc.Count;
                total += _dohBySrc.Count;
                total += _asnSeenAnywhere.Count;
                total += _asnSeenOnSensitive.Count;
            }
            catch
            {
                // Metrics must never break detection; swallow any transient errors.
            }

            yield return new Measurement<long>(
                total,
                new KeyValuePair<string, object?>("scope", "all"));
        }

        // ===== Existing per-rule state (R001–R022) =====
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<int, DateTime>> _sourceToPorts = new(StringComparer.Ordinal); // R001 (legacy)
        private static readonly ConcurrentDictionary<(string Src, string Dst), ConcurrentDictionary<int, DateTime>> _srcDstToPorts = new(); // R001 (per (src,dst) -> ports)
        private static readonly ConcurrentDictionary<string, List<DateTime>> _packetTimes = new(StringComparer.Ordinal); // R023/R029/R038 light rate-limiters
        private sealed class FloodBucket
        {
            public int Packets;
            public int Syn;
            public int Ack;
            public long Bytes;
            public long LatestTimestampTicks;
        }

        private sealed class FloodWindow
        {
            // One bucket per 100 ms limits state under dense, benign traffic.
            // A bucket starting before the cutoff is conservatively excluded,
            // so boundary approximation cannot inflate the evidence score.
            public readonly SortedDictionary<long, FloodBucket> Buckets = new();
            public DateTime LastObserved;
        }

        private static readonly ConcurrentDictionary<string, FloodWindow> _floodWindows =
            new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<(string Src, string Dst, int DstPort), List<DateTime>> _authAttempts = new();
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dnsQueries = new(StringComparer.Ordinal);   // R006
        private static readonly ConcurrentDictionary<(string Src, string Dst, int Port, string Protocol), List<(DateTime ts, int bytes)>> _beaconing = new();        // R007
        private static readonly ConcurrentDictionary<string, List<(DateTime ts, int bytes)>> _exfilBytes = new(StringComparer.Ordinal); // R008
        private sealed class ArpClaimState
        {
            public ArpClaimState(string mac, DateTime now) { ConfirmedMac = mac; LastSeen = now; }
            public string ConfirmedMac;
            public string? CandidateMac;
            public DateTime CandidateSince;
            public int CandidateCount;
            public DateTime LastSeen;
        }

        private static readonly ConcurrentDictionary<string, ArpClaimState> _arpTable = new(StringComparer.Ordinal); // R015, per claimed IPv4
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dhcpActivity = new(StringComparer.Ordinal); // R011, per client

        // Noisy-but-legit high ports to ignore in R013
        private static readonly HashSet<int> _uncommonPortAllow = new()
        {
            5353,              // mDNS
            1900,              // SSDP
            5228, 5229, 5230,  // Google Play / FCM
            27015, 27036, 27037, 27050 // Steam / Valve telemetry
        };

        private static HashSet<string> _blacklistedCountries = new(StringComparer.OrdinalIgnoreCase) { "CN", "RU", "KP", "IR" };

        // Common authentication ports (used in brute force and admin detection)
        private static readonly HashSet<int> AuthPorts = new()
        {
            22,    // SSH
            3389,  // RDP
            5985,  // WinRM (HTTP)
            5986,  // WinRM (HTTPS)
            23,    // Telnet
            21,    // FTP
            143,   // IMAP
            110,   // POP3
            25,    // SMTP
            465,   // SMTPS
            993,   // IMAPS
            995    // POP3S
        };

        // ===== New per-rule state (R017–R022, already present) =====
        private static readonly ConcurrentDictionary<(string Src, int Port, string Protocol), ConcurrentDictionary<string, DateTime>> _hostSweeps = new(); // R017
        private static readonly Regex _b64Like = new(@"[A-Za-z0-9+/_-]{80,}={0,2}", RegexOptions.Compiled); // R019
        private static readonly ConcurrentDictionary<string, List<DateTime>> _icmpTimes = new(StringComparer.Ordinal); // R021
        private static readonly ConcurrentDictionary<string, List<(DateTime ts, int bytes)>> _icmpWindow = new(StringComparer.Ordinal); // R021 per-source samples for windowed ICMP analysis
        private static readonly ConcurrentDictionary<string, long> _icmpBytes = new(StringComparer.Ordinal);           // R021
        private static readonly ConcurrentDictionary<string, List<DateTime>> _nxdomain = new(StringComparer.Ordinal);  // R022

        // ===== ARP parsing hints =====
        // Only parse explicit ARP is-at claims, not arbitrary IP/MAC pairs in logs.
        // Both common wire-summary orders are supported.
        private static readonly Regex _arpIsAtRegex = new(
            @"(?i)\b(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+is-at\s+(?<mac>(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})\b",
            RegexOptions.Compiled);
        private static readonly Regex _arpAlternateIsAtRegex = new(
            @"(?i)\bis-at\s+(?<ip>\d{1,3}(?:\.\d{1,3}){3})\s+(?<mac>(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2})\b",
            RegexOptions.Compiled);

        // ===== HTTP header parsing aids =====
        private static readonly Regex _httpHostHeaderRx =
            new(@"(?im)^\s*Host\s*:\s*\S+", RegexOptions.Compiled);

        private static readonly Regex _httpRequestLineRx = new(
            @"\A(?<method>GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\s+(?<uri>\S+)\s+HTTP/1\.(?<minor>[01])\r?\n",
            RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex _httpAuthorityHeaderRx = new(
            @"(?im)^\s*:authority\s*:\s*\S+", RegexOptions.Compiled);

        private static bool TryObservedHttpRequestLine(string? info, out string method, out string uri, out bool http11)
        {
            method = uri = string.Empty;
            http11 = false;
            if (string.IsNullOrWhiteSpace(info) || info.Length > 65536) return false;
            var match = _httpRequestLineRx.Match(info);
            if (!match.Success) return false;
            method = match.Groups["method"].Value.ToUpperInvariant();
            uri = match.Groups["uri"].Value;
            http11 = match.Groups["minor"].Value == "1";
            return true;
        }

        private static bool IsRecognizedHttpMethod(string? method)
            => method != null && Regex.IsMatch(method, @"\A(GET|POST|PUT|DELETE|HEAD|PATCH|OPTIONS)\z",
                RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        // ===== Extra regex helpers for R040–R049 =====
        private static readonly Regex _httpHostCaptureRx =
            new(@"(?im)^\s*Host\s*:\s*(?<host>[^\s\r\n:]+)", RegexOptions.Compiled);

        private static readonly Regex _authBasicRx =
            new(@"(?im)^\s*Authorization\s*:\s*Basic\s+[A-Za-z0-9+/\=]{10,}", RegexOptions.Compiled);

        private static readonly Regex _dohDnsParamRx =
            new(@"(?i)[\?&]dns=([A-Za-z0-9_\-+/=]{8,})", RegexOptions.Compiled);

        // ===== Helper: naive root-domain extraction for SNI/Host comparison =====
        private static string RootDomain(string host)
        {
            if (string.IsNullOrWhiteSpace(host)) return string.Empty;
            var h = host.Trim().TrimEnd('.').ToLowerInvariant();
            if (IPAddress.TryParse(h, out _)) return h;

            var parts = h.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 2) return h;
            return $"{parts[^2]}.{parts[^1]}";
        }

        // ===== Additional per-rule state (R023–R036) =====
        // Novel TLS/SSH fingerprint novelty (counts within memory-bounded maps)
        private static readonly ConcurrentDictionary<string, (int Count, DateTime FirstSeen, DateTime LastSeen)> _ja4Counts = new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, (int Count, DateTime FirstSeen, DateTime LastSeen)> _sshFpCounts = new(StringComparer.Ordinal); // hassh or ja4ssh

        // Admin lateral sweep (internal): src+admin-port -> distinct internal destinations
        private static readonly ConcurrentDictionary<(string Src, int Port), ConcurrentDictionary<string, DateTime>> _adminSweeps = new();

        // DNS TXT exfil-ish tracking
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dnsTxtBySrc = new(StringComparer.Ordinal);

        // Per (src,dst) byte accumulator to single external host
        private static readonly ConcurrentDictionary<(string Src, string Dst), List<(DateTime ts, int bytes)>> _pairBytes = new();

        // ===== Strategy detectors state (new: R037–R039) =====

        // R037: JA4 drift per SNI (per-SNI map of JA4 -> (count, lastSeen))
        private static readonly ConcurrentDictionary<string, List<(DateTime Ts, string Fingerprint)>> _sniJa4Drift =
            new(StringComparer.OrdinalIgnoreCase);

        // R038: QUIC high-entropy SNI + DoH surge (per-source windows)
        private static readonly ConcurrentDictionary<string, List<DateTime>> _quicHiEntropyBySrc =
            new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dohBySrc =
            new(StringComparer.Ordinal);

        // R039: ASN novelty on sensitive networks
        private static readonly ConcurrentDictionary<string, (DateTime FirstSeen, DateTime LastSeen)> _asnSeenAnywhere =
            new(StringComparer.Ordinal);
        private static readonly ConcurrentDictionary<string, DateTime> _asnSeenOnSensitive =
            new(StringComparer.Ordinal);

        // === Utility for local bounded maps (JA4 / SSH rarity) ===
        private static void BoundedMerge(ConcurrentDictionary<string, (int Count, DateTime FirstSeen, DateTime LastSeen)> map, string key, DateTime now, int maxKeys = 5000)
        {
            var cur = map.AddOrUpdate(key, _ => (1, now, now), (_, prev) => (prev.Count + 1, prev.FirstSeen, now));
            if (map.Count > maxKeys)
            {
                // Evict ~10% oldest by LastSeen (best-effort)
                var cutoff = now.AddMinutes(-60);
                foreach (var kv in map.Where(kv => kv.Value.LastSeen < cutoff).Take(Math.Max(1, map.Count / 10)).ToList())
                    map.TryRemove(kv.Key, out _);
            }
        }

        // Generic upper bound for any ConcurrentDictionary (best-effort, non-alloc-friendly but rarely hit).
        private static void BoundDictionary<TKey, TValue>(ConcurrentDictionary<TKey, TValue> map, int maxEntries)
            where TKey : notnull
        {
            if (maxEntries <= 0) return;
            var count = map.Count;
            if (count <= maxEntries) return;

            int toRemove = Math.Max(1, count - maxEntries);
            // We don't know "oldest"; just drop some keys. Time-based eviction is handled elsewhere.
            foreach (var key in map.Keys.Take(toRemove).ToList())
                map.TryRemove(key, out _);
        }

        // TCP flag tokens are not arbitrary substrings ("SYNTHETIC" must not
        // impersonate SYN, and lowercase packet-decoder flags remain valid).
        private static readonly Regex TcpSynToken = new(
            @"(?<![A-Za-z0-9])SYN(?![A-Za-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);
        private static readonly Regex TcpAckToken = new(
            @"(?<![A-Za-z0-9])ACK(?![A-Za-z0-9])",
            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant | RegexOptions.Compiled);

        // ===== R001 Port Scan (TCP SYN only, per (src,dst)) =====
        private static bool DetectPortScan(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                BoundDictionary(_srcDstToPorts, 20000);

                if (record.Source is not { Length: > 0 } src) return false;
                if (string.IsNullOrWhiteSpace(record.Destination)) return false;
                if (!string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) return false;

                // SYN w/o ACK is a scan signal; ignore pure ACKs/data
                bool syn = TcpSynToken.IsMatch(record.Flags ?? string.Empty);
                bool ack = TcpAckToken.IsMatch(record.Flags ?? string.Empty);
                if (!syn || ack) return false;

                if (record.DestinationPort is not int dport || dport is < 1 or > 65535) return false;

                int window = _cfg.PortScanWindowSeconds ?? PortScanWindowSeconds;
                int threshold = ScaleCount(_cfg.PortScanThreshold ?? PortScanThreshold, s);

                var map = _srcDstToPorts.GetOrAdd((src, record.Destination), _ => new ConcurrentDictionary<int, DateTime>());
                map[dport] = now;

                // Basic per-(src,dst) bounding to avoid pathological scans
                const int maxPortsPerPair = 4096;
                if (map.Count > maxPortsPerPair)
                {
                    var cutoffHard = now.AddSeconds(-window);
                    foreach (var k in map.Where(kv => kv.Value < cutoffHard || kv.Value > now).Select(kv => kv.Key).ToList())
                        map.TryRemove(k, out _);

                    // If still oversized, drop oldest few
                    if (map.Count > maxPortsPerPair)
                    {
                        foreach (var k in map.OrderBy(kv => kv.Value).Take(map.Count - maxPortsPerPair).Select(kv => kv.Key).ToList())
                            map.TryRemove(k, out _);
                    }
                }

                // evict old ports for this (src,dst)
                var cutoff = now.AddSeconds(-window);
                foreach (var k in map.Where(kv => kv.Value < cutoff || kv.Value > now).Select(kv => kv.Key).ToList())
                    map.TryRemove(k, out _);

                int uniquePorts = map.Count;
                if (uniquePorts >= threshold)
                {
                    if (SuppressRepeat(now, "R001", src, record.Destination, dport)) return false;

                    // severity ramps with evidence
                    var sev = uniquePorts >= threshold * 4 ? SeverityLevel.Critical
                             : uniquePorts >= threshold * 2 ? SeverityLevel.High
                             : SeverityLevel.Medium;

                    detection = new DetectionEvent
                    {
                        RuleId = "R001",
                        Description = $"Possible TCP port scan {src} ⇒ {record.Destination} ({uniquePorts} ports in {window}s)",
                        SourceIp = src,
                        DestinationIp = record.Destination,
                        DestinationPort = dport,
                        Protocol = "TCP",
                        Severity = sev,
                        Count = uniquePorts,
                        WindowSeconds = window
                    };
                    map.Clear();
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectPortScan error: {ex}"); }
            return false;
        }

        // ===== R002 Flood / DoS =====
        private static bool DetectFlood(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                BoundDictionary(_floodWindows, 50000);

                if (string.IsNullOrWhiteSpace(record.Source)
                    || string.IsNullOrWhiteSpace(record.Destination)) return false;
                var src = record.Source;
                // SYN volume toward one service must not be manufactured by
                // aggregating unrelated destinations from a busy scanner.
                // Distinct destination services may be busy independently. Do
                // not combine their SYN/ACK, packet or byte counters.
                var floodKey = $"R002:{src}->{record.Destination}:{record.DestinationPort}";

                var window = _cfg.FloodWindowSeconds ?? FloodWindowSeconds;
                var pktThreshold = ScaleCount(_cfg.FloodThreshold ?? FloodThreshold, s);
                var byteThreshold = ScaleBytes(_cfg.FloodByteThreshold ?? FloodByteThreshold, s);
                var synAckRatioThresh = ScaleFloat(_cfg.SynAckRatioThreshold ?? SynAckRatioThreshold, s);

                bool syn = TcpSynToken.IsMatch(record.Flags ?? string.Empty);
                bool ack = TcpAckToken.IsMatch(record.Flags ?? string.Empty);
                var state = _floodWindows.GetOrAdd(floodKey, _ => new FloodWindow());
                lock (state)
                {
                    const long bucketTicks = TimeSpan.TicksPerMillisecond * 100;
                    long bucketStart = now.Ticks - now.Ticks % bucketTicks;
                    long cutoff = now.AddSeconds(-window).Ticks;

                    // Remove expired and future observations. Future timestamps
                    // must never contribute to an out-of-order replay window.
                    foreach (var key in state.Buckets
                        .Where(kv => kv.Key < cutoff || kv.Value.LatestTimestampTicks > now.Ticks)
                        .Select(kv => kv.Key).ToList())
                        state.Buckets.Remove(key);

                    if (!state.Buckets.TryGetValue(bucketStart, out var bucket))
                        state.Buckets[bucketStart] = bucket = new FloodBucket();
                    bucket.Packets++;
                    if (syn) bucket.Syn++;
                    if (ack) bucket.Ack++;
                    bucket.Bytes += Math.Max(0, record.Length);
                    bucket.LatestTimestampTicks = Math.Max(bucket.LatestTimestampTicks, now.Ticks);
                    state.LastObserved = now;

                    // Bounded even if a deployment configures a very long
                    // window. Losing oldest evidence can reduce recall, but
                    // must never manufacture a positive.
                    const int maxBucketsPerFlow = 4096;
                    while (state.Buckets.Count > maxBucketsPerFlow)
                        state.Buckets.Remove(state.Buckets.Keys.First());

                    long pktCount = 0, synCount = 0, ackCount = 0, byteCount = 0;
                    foreach (var sample in state.Buckets.Values)
                    {
                        pktCount += sample.Packets;
                        synCount += sample.Syn;
                        ackCount += sample.Ack;
                        byteCount += sample.Bytes;
                    }

                    if (pktCount < pktThreshold || byteCount < byteThreshold) return false;
                    double synAckRatio = ackCount > 0 ? (double)synCount / ackCount : synCount;
                    if (synAckRatio < synAckRatioThresh) return false;
                    if (SuppressRepeat(now, "R002", src, record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R002",
                        Description = $"Possible flood/DoS from {src} (pkts={pktCount}, bytes={byteCount}/{window}s, SYN/ACK={synAckRatio:F1})",
                        SourceIp = src,
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.Critical,
                        Count = (int)Math.Min(pktCount, int.MaxValue),
                        WindowSeconds = window
                    };
                    state.Buckets.Clear();
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectFlood error: {ex}"); }
            return false;
        }

        // ===== R003 Threat Feed Hit =====
        private static bool DetectThreatFeedHit(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (string.IsNullOrEmpty(record.Destination)) return false;

                // Absolute FQDNs may carry a trailing DNS root dot; preserve
                // exact-indicator matching while normalizing that equivalent form.
                var host = record.Destination.Trim().TrimEnd('.').ToLowerInvariant();
                if (ThreatFeedService.MaliciousHosts.Contains(host))
                {
                    if (SuppressRepeat(now, "R003", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R003",
                        Description = $"Traffic to known malicious host: {host}",
                        SourceIp = NS(record.Source),
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.Critical,
                        Count = 1,
                        WindowSeconds = 0
                    };

                    // Penalize the observed (port,proto) so R013 won't "learn away" a bad service.
                    if (record.DestinationPort is int p && !string.IsNullOrWhiteSpace(record.Protocol))
                        AllowListLearner.MarkBad(p, record.Protocol, now, "threat-feed");

                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectThreatFeedHit error: {ex}"); }
            return false;
        }

        // ===== R004 Brute Force (tightened) =====
        private static bool DetectBruteForce(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                BoundDictionary(_authAttempts, 50000);

                if (record.Source is not { Length: > 0 } src ||
                    record.DestinationPort is not int dstPort ||
                    !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)) // must be TCP
                    return false;

                // TCP handshakes, SSH banners, remote-admin port traffic,
                // and FTP USER/PASS command strings do NOT establish failed
                // credentials. Corroborate with an observed failure outcome
                // before counting a brute-force attempt. Do not assume that
                // an encrypted SSH/RDP session is a login failure.
                bool authPort = AuthPorts.Contains(dstPort);
                bool authService = record.ApplicationService is { } service
                    && (service.Equals("SSH", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("RDP", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("WINRM", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("FTP", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("IMAP", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("POP3", StringComparison.OrdinalIgnoreCase)
                        || service.Equals("SMTP", StringComparison.OrdinalIgnoreCase));

                if ((!authPort && !authService)
                    || !Regex.IsMatch(record.Info ?? string.Empty,
                        @"\b(?:failed password|authentication failed|authentication failure|login failed|invalid credentials|invalid password|login incorrect)\b",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                    return false;

                // Track per (src,dstIp,dstPort) so scans across many hosts don’t look like brute force
                string dstKey = $"{NS(record.Destination)}:{dstPort}";
                var attempts = _authAttempts.GetOrAdd((src, NS(record.Destination), dstPort), _ => new List<DateTime>(32));

                var window = _cfg.BruteForceWindowSeconds ?? BruteForceWindowSeconds;
                var baseThreshold = ScaleCount(_cfg.BruteForceThreshold ?? BruteForceThreshold, s);
                var effectiveThreshold = authPort ? Math.Max(3, baseThreshold / 2) : baseThreshold;

                lock (attempts)
                {
                    attempts.Add(now);
                    // keep only attempts to THIS dstKey in-window
                    int write = 0;
                    for (int i = 0; i < attempts.Count; i++)
                        if (attempts[i] <= now && attempts[i] >= now.AddSeconds(-window)) attempts[write++] = attempts[i];
                    if (write != attempts.Count) attempts.RemoveRange(write, attempts.Count - write);

                    int count = attempts.Count;
                    if (count >= effectiveThreshold)
                    {
                        if (SuppressRepeat(now, "R004", src, record.Destination, record.DestinationPort)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R004",
                            Description = $"Probable brute-force on {dstKey} from {src} ({count}/{window}s)",
                            SourceIp = src,
                            DestinationIp = record.Destination,
                            DestinationPort = record.DestinationPort,
                            Protocol = NP(record.Protocol),
                            Severity = authPort ? SeverityLevel.High : SeverityLevel.Medium,
                            Count = count,
                            WindowSeconds = window
                        };
                        attempts.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectBruteForce error: {ex}"); }
            return false;
        }

        // ===== R005 Suspicious Protocol (prefer ApplicationService, fallback to Protocol) =====
        private static bool DetectSuspiciousProtocol(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                // Protocol classification without a source, destination and
                // observed service endpoint is insufficient to attribute a
                // network exposure finding to a real traffic flow.
                if (string.IsNullOrWhiteSpace(record.Source)
                    || string.IsNullOrWhiteSpace(record.Destination)
                    || record.DestinationPort is not int port || port <= 0 || port > 65535)
                    return false;

                string proto = record.ApplicationService?.Trim().ToUpperInvariant()
                               ?? record.Protocol?.Trim().ToUpperInvariant()
                               ?? string.Empty;

                if (proto is "TELNET" or "FTP" or "SMB" or "SNMP")
                {
                    if (SuppressRepeat(now, "R005", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R005",
                        Description = $"Suspicious/insecure protocol usage: {proto}",
                        SourceIp = NS(record.Source),
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = 1,
                        WindowSeconds = 0
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectSuspiciousProtocol error: {ex}"); }
            return false;
        }

        // R007/R008/R010 need a real Internet endpoint. A null, hostname,
        // loopback, RFC1918, carrier NAT, documentation or multicast address
        // must not be silently treated as publicly routable evidence.
        // This intentionally does not alter the legacy IsPrivateIp helper
        // used by other detectors.
        private static bool IsPublicLegacyEgressIp(string? endpoint)
        {
            if (string.IsNullOrWhiteSpace(endpoint)
                || !IPAddress.TryParse(endpoint, out var ip))
                return false;

            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            if (IPAddress.IsLoopback(ip)) return false;

            var bytes = ip.GetAddressBytes();
            if (bytes.Length == 4)
            {
                int a = bytes[0], b = bytes[1], c = bytes[2];
                return a != 0 && a != 10 && a != 127 && a < 224
                    && !(a == 100 && b >= 64 && b <= 127)
                    && !(a == 169 && b == 254)
                    && !(a == 172 && b >= 16 && b <= 31)
                    && !(a == 192 && (b == 168 || (b == 0 && c == 0) || (b == 0 && c == 2)))
                    && !(a == 198 && (b == 18 || b == 19 || (b == 51 && c == 100)))
                    && !(a == 203 && b == 0 && c == 113);
            }

            if (bytes.Length != 16 || ip.Equals(IPAddress.IPv6Any)
                || ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal
                || ip.IsIPv6Multicast)
                return false;
            // fc00::/7 ULA and 2001:db8::/32 documentation.
            if ((bytes[0] & 0xFE) == 0xFC
                || (bytes[0] == 0x20 && bytes[1] == 0x01
                    && bytes[2] == 0x0D && bytes[3] == 0xB8))
                return false;
            return true;
        }

        // ===== R006 DNS Anomalies (query volume / content hypothesis) =====
        private static bool DetectDnsAnomaly(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                bool isDns = string.Equals(record.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                             || (string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                                 && record.DestinationPort == 53);
                // Responses, missing query names and port-only UDP traffic
                // cannot be counted as distinct observed DNS requests.
                if (!isDns || record.DnsIsResponse
                    || string.IsNullOrWhiteSpace(record.Source)
                    || string.IsNullOrWhiteSpace(record.Destination)
                    || string.IsNullOrWhiteSpace(record.DnsQname)
                    || (record.DestinationPort.HasValue
                        && (record.DestinationPort.Value < 1 || record.DestinationPort.Value > 65535)))
                    return false;

                string src = record.Source.Trim();
                string qname = record.DnsQname.Trim().TrimEnd('.');
                if (qname.Length == 0 || qname.Length > 253
                    || qname.Any(char.IsWhiteSpace)
                    || qname.Split('.').Any(label => label.Length is < 1 or > 63))
                    return false;

                BoundDictionary(_dnsQueries, 20000);
                int window = _cfg.DnsWindowSeconds ?? DnsWindowSeconds;
                int threshold = ScaleCount(_cfg.DnsThreshold ?? DnsThreshold, s);
                double entropyThresh = ScaleFloat(_cfg.DnsEntropyThreshold ?? DnsEntropyThreshold, s);
                double avgLabelLenThresh = ScaleFloat(_cfg.DnsAvgLabelLenThreshold ?? DnsAvgLabelLenThreshold, s);
                int queryLenThresh = ScaleCount(_cfg.DnsQueryLenThreshold ?? DnsQueryLenThreshold, s);

                var list = _dnsQueries.GetOrAdd(src, _ => new List<DateTime>(capacity: Math.Max(threshold * 2, 32)));
                lock (list)
                {
                    // The evaluation clock may move backwards during replay,
                    // capture recovery or reordering. Never count future events.
                    DateTime cutoff = now.AddSeconds(-window);
                    list.RemoveAll(ts => ts < cutoff || ts > now);
                    list.Add(now);
                    if (list.Count < threshold) return false;

                    var labels = qname.Split('.');
                    double avgLen = labels.Average(label => label.Length);
                    string longest = labels.OrderByDescending(label => label.Length).First();
                    bool suspiciousContent =
                        (longest.Length >= Math.Max(20, avgLabelLenThresh)
                            && ShannonEntropy(longest) > entropyThresh)
                        || (qname.Length > queryLenThresh * 2 && avgLen > avgLabelLenThresh);

                    int count = list.Count;
                    // Clear even when cooldown suppresses an event. Otherwise
                    // repeated benign requests grow state throughout cooldown.
                    list.Clear();
                    if (SuppressRepeat(now, "R006", src, record.Destination, record.DestinationPort))
                        return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R006",
                        Description = suspiciousContent
                            ? $"Possible DNS tunneling from {src} ({count}/{window}s, high-entropy/long query)"
                            : $"Elevated DNS request volume from {src} ({count}/{window}s; query content not corroborated)",
                        SourceIp = src,
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = suspiciousContent ? SeverityLevel.High : SeverityLevel.Medium,
                        Count = count,
                        WindowSeconds = window
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDnsAnomaly error: {ex}"); }
            return false;
        }

        // ===== R007 C2 Beaconing (periodicity candidate, not proof of C2) =====
        private static bool DetectBeaconing(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (string.IsNullOrWhiteSpace(record.Source)
                    || !IsPublicLegacyEgressIp(record.Destination)
                    || record.Length <= 0
                    || record.DestinationPort is not int port || port is < 1 or > 65535
                    || !(string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                string src = record.Source.Trim(), dst = record.Destination!.Trim();
                BoundDictionary(_beaconing, 20000);
                var key = (Src: src, Dst: dst, Port: port, Protocol: record.Protocol!.ToUpperInvariant());
                var list = _beaconing.GetOrAdd(key, _ => new List<(DateTime ts, int bytes)>(capacity: 64));

                lock (list)
                {
                    // Bound stale and future observations before considering
                    // cadence. Preserve ordering under out-of-order ingestion.
                    DateTime cutoff = now.AddMinutes(-30);
                    list.RemoveAll(sample => sample.ts < cutoff || sample.ts > now);
                    list.Add((now, record.Length));
                    list.Sort((a, b) => a.ts.CompareTo(b.ts));
                    if (list.Count > 128) list.RemoveRange(0, list.Count - 128);

                    int minSamples = ScaleCount(_cfg.BeaconMinSamples ?? BeaconMinSamples, s);
                    if (list.Count < minSamples) return false;
                    double elapsed = (list[^1].ts - list[0].ts).TotalSeconds;
                    int minObs = ScaleCount(_cfg.BeaconMinObservationSeconds ?? BeaconMinObservationSeconds, s);
                    if (elapsed < minObs) return false;

                    var intervals = new List<double>(list.Count - 1);
                    for (int i = 1; i < list.Count; i++)
                        intervals.Add((list[i].ts - list[i - 1].ts).TotalSeconds);
                    // Packet bursts and duplicate timestamps are not beacons.
                    if (intervals.Any(seconds => seconds < 1)) return false;

                    double avg = intervals.Average();
                    double variance = intervals.Sum(x => (x - avg) * (x - avg));
                    double stddev = Math.Sqrt(variance / intervals.Count);
                    double frac = _cfg.BeaconStdDevFraction ?? BeaconStdDevFraction;
                    bool lowJitter = stddev < Math.Max(0.5, avg * frac);
                    // A mathematically perfect cadence has zero variance.
                    // Autocorrelation is undefined there, not negative.
                    bool periodic = variance <= 1e-12
                        || AutocorrSpike(intervals, _cfg.BeaconAutocorrLags ?? BeaconAutocorrLags);
                    double avgBytes = list.Average(sample => (double)sample.bytes);
                    if (!lowJitter || !periodic || avgBytes > 600) return false;

                    int count = list.Count;
                    list.Clear();
                    if (SuppressRepeat(now, "R007", src, dst, record.DestinationPort))
                        return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R007",
                        Description = $"Possible periodic outbound beacon {src} → {dst} (mean={avg:F1}s, jitter={stddev:F2}, avgBytes={avgBytes:F0})",
                        SourceIp = src,
                        DestinationIp = dst,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = avg >= 30 && avg <= 600 ? SeverityLevel.High : SeverityLevel.Medium,
                        Count = count,
                        WindowSeconds = (int)Math.Round(elapsed)
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectBeaconing error: {ex}"); }
            return false;
        }

        // ===== R008 Exfiltration (egress volume candidate, not proof of theft) =====
        private static bool DetectExfiltration(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (string.IsNullOrWhiteSpace(record.Source)
                    || !IsPublicLegacyEgressIp(record.Destination)
                    || record.Length <= 0
                    || record.DestinationPort is not int port || port is < 1 or > 65535
                    || !(string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                string src = record.Source.Trim();
                BoundDictionary(_exfilBytes, 20000);
                int window = _cfg.ExfilWindowSeconds ?? ExfilWindowSeconds;
                long thresholdBytes = ScaleBytes(_cfg.ExfilThresholdBytes ?? ExfilThresholdBytes, s);
                var list = _exfilBytes.GetOrAdd(src, _ => new List<(DateTime ts, int bytes)>(capacity: 32));
                lock (list)
                {
                    DateTime cutoff = now.AddSeconds(-window);
                    list.RemoveAll(sample => sample.ts < cutoff || sample.ts > now);
                    list.Add((now, record.Length));

                    // Length is int, but the sum can exceed Int32.MaxValue.
                    long totalBytes = list.Sum(sample => (long)sample.bytes);
                    if (totalBytes < thresholdBytes) return false;

                    list.Clear();
                    if (SuppressRepeat(now, "R008", src, record.Destination, record.DestinationPort))
                        return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R008",
                        Description = $"High outbound volume from {src} ({totalBytes} bytes / {window}s; exfiltration unconfirmed)",
                        SourceIp = src,
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.Critical,
                        Count = (int)Math.Min(int.MaxValue, totalBytes),
                        WindowSeconds = window
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectExfiltration error: {ex}"); }
            return false;
        }

        // ===== R009 VPN/Proxy usage (classification candidate) =====
        private static bool DetectVpnProxy(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (record.IsVpn != true && record.IsProxy != true) return false;
                if (string.IsNullOrWhiteSpace(record.Source)
                    || string.IsNullOrWhiteSpace(record.Destination)
                    || record.DestinationPort is not int port || port is < 1 or > 65535
                    || !(string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                string src = record.Source.Trim();
                if (SuppressRepeat(now, "R009", src, record.Destination, port)) return false;

                detection = new DetectionEvent
                {
                    RuleId = "R009",
                    Description = $"VPN/proxy usage observed from {src} (authorization not determined)",
                    SourceIp = src,
                    DestinationIp = record.Destination,
                    DestinationPort = port,
                    Protocol = NP(record.Protocol),
                    Severity = SeverityLevel.Medium,
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectVpnProxy error: {ex}"); }
            return false;
        }

        // ===== R010 Destination GeoIP policy (not WHOIS registration) =====
        private static bool DetectBlacklistedCountry(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (string.IsNullOrWhiteSpace(record.Source)
                    || !IsPublicLegacyEgressIp(record.Destination)
                    || string.IsNullOrWhiteSpace(record.DstCountryIso2))
                    return false;

                string country = record.DstCountryIso2.Trim().ToUpperInvariant();
                // WHOIS country is registration metadata, not the destination
                // geolocation. Source country alone is also not egress evidence.
                if (country.Length != 2 || !country.All(c => c is >= 'A' and <= 'Z')
                    || !_blacklistedCountries.Contains(country))
                    return false;

                string src = record.Source.Trim();
                if (SuppressRepeat(now, "R010", src, record.Destination, record.DestinationPort))
                    return false;

                detection = new DetectionEvent
                {
                    RuleId = "R010",
                    Description = $"Outbound destination GeoIP policy country {country} (geolocation is approximate)",
                    SourceIp = src,
                    DestinationIp = record.Destination,
                    DestinationPort = record.DestinationPort,
                    Country = country,
                    Protocol = NP(record.Protocol),
                    Severity = SeverityLevel.High,
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectBlacklistedCountry error: {ex}"); }
            return false;
        }

        // ===== R011–R015: precision-oriented legacy detectors =====
        private static bool TryNormalizeUnicastMac(string? value, out string normalized)
        {
            normalized = string.Empty;
            if (string.IsNullOrWhiteSpace(value) ||
                !Regex.IsMatch(value.Trim(), @"^(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$"))
                return false;

            normalized = value.Trim().Replace(":", "").Replace("-", "").ToUpperInvariant();
            int firstOctet = Convert.ToInt32(normalized.Substring(0, 2), 16);
            return (firstOctet & 1) == 0 && normalized != "000000000000";
        }

        // R011: count client-originated DHCP requests per stable client, not all
        // DHCP traffic on the segment. Server responses and free-text labels do
        // not establish abuse; this remains a rate candidate, not a rogue-server verdict.
        private static bool DetectDhcpAbuse(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) ||
                    record.SourcePort != 68 || record.DestinationPort != 67 || record.Length <= 0)
                    return false;

                string clientKey;
                if (!string.IsNullOrWhiteSpace(record.MacSource))
                {
                    if (!TryNormalizeUnicastMac(record.MacSource, out var mac)) return false;
                    clientKey = "mac:" + mac;
                }
                else if (IsPrivateIp(record.Source) &&
                         IPAddress.TryParse(record.Source, out var sourceIp) &&
                         sourceIp.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
                {
                    clientKey = "ip:" + sourceIp;
                }
                else
                {
                    // DHCP discover packets can have 0.0.0.0 source; without a
                    // link-layer identity they cannot be attributed safely.
                    return false;
                }

                int window = _cfg.DhcpWindowSeconds ?? DhcpWindowSeconds;
                int threshold = ScaleCount(_cfg.DhcpThreshold ?? DhcpThreshold, s);
                BoundDictionary(_dhcpActivity, 4096);
                var list = _dhcpActivity.GetOrAdd(clientKey, _ => new List<DateTime>(Math.Max(threshold, 32)));
                int count;
                lock (list)
                {
                    DateTime cutoff = now.AddSeconds(-window);
                    list.RemoveAll(ts => ts < cutoff || ts > now);
                    list.Add(now);
                    count = list.Count;
                    if (count < threshold) return false;
                    list.Clear(); // bounded even while the cooldown suppresses output
                }

                if (SuppressRepeat(now, "R011", clientKey, null, null)) return false;
                detection = new DetectionEvent
                {
                    RuleId = "R011",
                    Description = $"High DHCP client-request rate ({count} in {window}s); authorization and cause unknown.",
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = 67,
                    Protocol = "UDP",
                    Severity = SeverityLevel.High,
                    Count = count,
                    WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDhcpAbuse error: {ex}"); }
            return false;
        }

        // R012: a textual certificate flag alone is not certificate evidence.
        // Structured validity/issuer metadata is necessary, and a self-issued
        // certificate is a trust-review candidate, not proof of interception.
        private static bool DetectSuspiciousTls(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (record.DestinationPort != 443 ||
                    !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase) ||
                    !IPAddress.TryParse(record.Source, out _) ||
                    !IPAddress.TryParse(record.Destination, out _))
                    return false;

                bool expired = record.CertValidTo.HasValue &&
                               record.CertValidTo.Value.ToUniversalTime() < now.ToUniversalTime();
                bool notYetValid = record.CertValidFrom.HasValue &&
                                   record.CertValidFrom.Value.ToUniversalTime() > now.ToUniversalTime();
                bool selfIssued = !string.IsNullOrWhiteSpace(record.TlsVersion) &&
                                  !string.IsNullOrWhiteSpace(record.CertIssuer) &&
                                  !string.IsNullOrWhiteSpace(record.CertSubject) &&
                                  string.Equals(record.CertIssuer.Trim(), record.CertSubject.Trim(),
                                      StringComparison.OrdinalIgnoreCase);
                if (!expired && !notYetValid && !selfIssued) return false;

                if (SuppressRepeat(now, "R012", NS(record.Source), record.Destination, 443)) return false;
                string reason = expired ? "expired" : notYetValid ? "not yet valid" : "self-issued";
                detection = new DetectionEvent
                {
                    RuleId = "R012",
                    Description = $"TLS certificate anomaly ({reason}); trust and authorization require validation.",
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = 443,
                    Protocol = "TCP",
                    Severity = SeverityLevel.Medium,
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectSuspiciousTls error: {ex}"); }
            return false;
        }

        // R013: unknown high ports are not evidence by themselves. Require a
        // TCP initial SYN or an explicitly identified UDP service. Do not echo
        // attacker-controlled application-service labels in alert descriptions.
        private static bool DetectUncommonPorts(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!record.DestinationPort.HasValue ||
                    record.DestinationPort.Value is <= 1024 or > 65535 ||
                    !IPAddress.TryParse(record.Source, out _) ||
                    !IPAddress.TryParse(record.Destination, out _))
                    return false;

                int port = record.DestinationPort.Value;
                if (_uncommonPortAllow.Contains(port)) return false;

                string proto = record.Protocol?.Trim().ToUpperInvariant() ?? "";
                if (proto != "TCP" && proto != "UDP") return false;
                bool isTcp = proto == "TCP";
                bool ephemeral = port >= 49152;
                if (!isTcp && ephemeral) return false;
                if (AllowListLearner.IsAllowed(port, proto, now)) return false;

                bool tcpInitialSyn = isTcp &&
                    (record.TcpFlags.HasValue
                        ? (record.TcpFlags.Value & 0x16) == 0x02
                        : Regex.IsMatch(record.Flags ?? "", @"(?i)\bSYN\b") &&
                          !Regex.IsMatch(record.Flags ?? "", @"(?i)\b(ACK|RST|FIN)\b"));
                bool udpService = !isTcp && record.Length > 0 &&
                                  !string.IsNullOrWhiteSpace(record.ApplicationService);
                if (!tcpInitialSyn && !udpService) return false;
                if (ephemeral && string.IsNullOrWhiteSpace(record.ApplicationService))
                    return false;

                string standardName =
                    PortServiceResolver.TryGetServiceInfo(port, proto, out var standardInfo) &&
                    !standardInfo.Source.StartsWith("Heuristic", StringComparison.OrdinalIgnoreCase)
                        ? standardInfo.Name : "unknown";
                bool unknown = string.Equals(standardName, "unknown", StringComparison.OrdinalIgnoreCase);
                bool mismatch = !unknown &&
                                !string.IsNullOrWhiteSpace(record.ApplicationService) &&
                                !string.Equals(standardName.Trim(), record.ApplicationService.Trim(),
                                    StringComparison.OrdinalIgnoreCase);
                if (!unknown && !mismatch) return false;

                double anomaly = unknown ? 0.85 : 0.75;
                if (!IsPrivateIp(record.Destination))
                    anomaly = Math.Min(1.0, anomaly + 0.05);
                double threshold = _cfg.UncommonPortsAnomalyThreshold ?? UncommonPortsAnomalyThresholdDefault;
                if (anomaly < threshold) return false;

                if (SuppressRepeat(now, "R013", NS(record.Source), record.Destination, port))
                    return false;
                detection = new DetectionEvent
                {
                    RuleId = "R013",
                    Description = unknown
                        ? $"Unrecognized service on {port}/{proto} (local registry); anomaly={anomaly:F2}."
                        : $"Service/port classification mismatch on {port}/{proto}; anomaly={anomaly:F2}.",
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = port,
                    Protocol = proto,
                    Severity = unknown ? SeverityLevel.Low :
                        (anomaly >= 0.85 ? SeverityLevel.High : SeverityLevel.Medium),
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectUncommonPorts error: {ex}"); }
            return false;
        }

        // R014: SMTP envelope addresses and AUTH LOGIN negotiation are not
        // passwords. Match a credential-bearing command only on an explicitly
        // unencrypted service, without persisting or echoing any secret.
        private static readonly Regex _ftpPassCommand = new(
            @"(?im)^\s*PASS\s+\S{1,256}\s*$", RegexOptions.Compiled);
        private static readonly Regex _smtpAuthPlainCommand = new(
            @"(?im)^\s*AUTH\s+PLAIN\s+[A-Za-z0-9+/=]{8,}\s*$", RegexOptions.Compiled);
        private static readonly Regex _httpBasicHeader = new(
            @"(?im)^\s*Authorization\s*:\s*Basic\s+[A-Za-z0-9+/=]{8,}\s*$", RegexOptions.Compiled);

        private static bool DetectCleartextCreds(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!IPAddress.TryParse(record.Source, out _) ||
                    !IPAddress.TryParse(record.Destination, out _) ||
                    record.Length <= 0 || !record.DestinationPort.HasValue ||
                    !string.IsNullOrWhiteSpace(record.TlsVersion) ||
                    !string.IsNullOrWhiteSpace(record.Sni) || record.IsQuic)
                    return false;

                int port = record.DestinationPort.Value;
                bool tcp = string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);
                bool http = string.Equals(record.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase);
                if (!tcp && !http) return false;

                string info = record.Info ?? "";
                string headers = record.HttpRequestHeaders ?? "";
                if (info.Length > 4096 || headers.Length > 4096) return false;

                string? service = null;
                if (tcp && port == 21 && _ftpPassCommand.IsMatch(info))
                    service = "FTP";
                else if (tcp && (port == 25 || port == 587) && _smtpAuthPlainCommand.IsMatch(info))
                    service = "SMTP";
                else if ((tcp || http) && (port == 80 || port == 8080 || port == 8000) &&
                         _httpBasicHeader.IsMatch(headers))
                    service = "HTTP";

                if (service == null) return false;
                if (SuppressRepeat(now, "R014", NS(record.Source), record.Destination, port)) return false;
                detection = new DetectionEvent
                {
                    RuleId = "R014",
                    Description = $"Possible cleartext credential submission on {service}; credential material not retained.",
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = port,
                    Protocol = NP(record.Protocol),
                    Severity = SeverityLevel.Critical,
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectCleartextCreds error: {ex}"); }
            return false;
        }

        // R015: a single changed ARP mapping can be a legitimate lease or
        // failover. Require two temporally distinct, header-consistent claims
        // of the new MAC within 30s before reporting a candidate conflict.
        private static bool DetectArpSpoofing(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!string.Equals(record.Protocol, "ARP", StringComparison.OrdinalIgnoreCase) ||
                    string.IsNullOrWhiteSpace(record.MacSource))
                    return false;

                string info = record.Info ?? "";
                if (info.Length > 2048) return false;
                var match = _arpIsAtRegex.Match(info);
                if (!match.Success) match = _arpAlternateIsAtRegex.Match(info);
                if (!match.Success) return false;

                string ip = match.Groups["ip"].Value;
                if (!IPAddress.TryParse(ip, out var claimedIp) ||
                    claimedIp.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork ||
                    !IsPrivateIp(ip) ||
                    !TryNormalizeUnicastMac(match.Groups["mac"].Value, out var claimedMac) ||
                    !TryNormalizeUnicastMac(record.MacSource, out var headerMac) ||
                    claimedMac != headerMac)
                    return false;

                // Contradictory sender attribution cannot seed a trusted mapping.
                if (IPAddress.TryParse(record.Source, out var sourceIp) &&
                    !sourceIp.Equals(IPAddress.Any) && !sourceIp.Equals(claimedIp))
                    return false;

                BoundDictionary(_arpTable, 50000);
                var state = _arpTable.GetOrAdd(ip, _ => new ArpClaimState(claimedMac, now));
                lock (state)
                {
                    if (now < state.LastSeen) return false;
                    state.LastSeen = now;
                    if (claimedMac == state.ConfirmedMac)
                    {
                        state.CandidateMac = null;
                        state.CandidateCount = 0;
                        return false;
                    }
                    if (claimedMac != state.CandidateMac ||
                        (now - state.CandidateSince).TotalSeconds > 30)
                    {
                        state.CandidateMac = claimedMac;
                        state.CandidateCount = 1;
                        state.CandidateSince = now;
                        return false;
                    }
                    if (now <= state.CandidateSince) return false;
                    state.CandidateCount++;
                    if (state.CandidateCount < 2) return false;
                    state.ConfirmedMac = claimedMac;
                    state.CandidateMac = null;
                    state.CandidateCount = 0;
                }

                if (SuppressRepeat(now, "R015", ip, null, null)) return false;
                detection = new DetectionEvent
                {
                    RuleId = "R015",
                    Description = "Repeated conflicting ARP is-at claims for a private IPv4 address; verify authorized address movement.",
                    SourceIp = ip,
                    Protocol = "ARP",
                    Severity = SeverityLevel.High,
                    Count = 2,
                    WindowSeconds = 30
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectArpSpoofing error: {ex}"); }
            return false;
        }

        // ===== R016 Reputation (AbuseIPDB) =====
        private static bool DetectReputation(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!IPAddress.TryParse(record.Source, out _) ||
                    !IsPublicLegacyEgressIp(record.Destination) ||
                    record.ReputationScore is not int score || score is < 0 or > 100 ||
                    record.ReputationIsMalicious == false ||
                    (record.ReputationReports.HasValue && record.ReputationReports.Value <= 0))
                    return false;

                // An explicit enrichment timestamp must be plausible and fresh.
                // Missing optional enrichment metadata preserves legacy score-only detection.
                if (record.ReputationLastSeen is DateTime lastSeen &&
                    (lastSeen.ToUniversalTime() > now.ToUniversalTime().AddMinutes(5) ||
                     lastSeen.ToUniversalTime() < now.ToUniversalTime().AddDays(-30)))
                    return false;

                int cutoff = s.AbuseIpdbThreshold();
                if (score < cutoff) return false;
                string src = record.Source!.Trim(), dst = record.Destination!.Trim();
                if (SuppressRepeat(now, "R016", src, dst, record.DestinationPort)) return false;

                detection = new DetectionEvent
                {
                    RuleId = "R016",
                    Description = $"AbuseIPDB destination reputation score {score} ≥ {cutoff} (enrichment requires review)",
                    SourceIp = src,
                    DestinationIp = dst,
                    DestinationPort = record.DestinationPort,
                    Protocol = NP(record.Protocol),
                    Severity = score >= 90 ? SeverityLevel.Critical : SeverityLevel.High,
                    Count = score,
                    WindowSeconds = 0
                };

                // A score alone must not poison the service learner.
                if (record.ReputationIsMalicious == true &&
                    record.ReputationReports.GetValueOrDefault() > 0 &&
                    record.DestinationPort is int port && port is >= 1 and <= 65535 &&
                    (string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase) ||
                     string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)))
                    AllowListLearner.MarkBad(port, record.Protocol!, now, "reputation");

                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectReputation error: {ex}"); }
            return false;
        }

        // ===== R017 Internal host sweep (same-port across many hosts) =====
        private static bool DetectHostSweep(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!IPAddress.TryParse(record.Source, out var sourceIp) ||
                    !IPAddress.TryParse(record.Destination, out var destinationIp) ||
                    !IsPrivateIp(record.Source) || !IsPrivateIp(record.Destination) ||
                    sourceIp.Equals(destinationIp) ||
                    record.DestinationPort is not int dport || dport is < 1 or > 65535 ||
                    record.Length <= 0)
                    return false;

                bool tcp = string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);
                bool udp = string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase);
                if (!tcp && !udp) return false;
                if (tcp && !(record.TcpFlags.HasValue
                    ? (record.TcpFlags.Value & 0x16) == 0x02
                    : Regex.IsMatch(record.Flags ?? "", @"(?i)\bSYN\b") &&
                      !Regex.IsMatch(record.Flags ?? "", @"(?i)\b(ACK|RST|FIN)\b")))
                    return false;

                BoundDictionary(_hostSweeps, 10000);
                string src = sourceIp.ToString(), dst = destinationIp.ToString();
                string protocol = tcp ? "TCP" : "UDP";
                int window = _cfg.HostSweepWindowSeconds ?? HostSweepWindowSeconds;
                int threshold = ScaleCount(_cfg.HostSweepDistinctHostsThreshold ?? HostSweepDistinctHostsThreshold, s);
                var key = (Src: src, Port: dport, Protocol: protocol);
                var map = _hostSweeps.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>());
                lock (map)
                {
                    DateTime cutoff = now.AddSeconds(-window);
                    foreach (var old in map.Where(kv => kv.Value < cutoff || kv.Value > now).Select(kv => kv.Key).ToArray())
                        map.TryRemove(old, out _);
                    map.AddOrUpdate(dst, now, (_, previous) => previous > now ? previous : now);

                    // Bounded per-key memory even when a configured threshold is very high.
                    int cap = Math.Max(256, Math.Min(8192, threshold * 2));
                    if (map.Count > cap)
                        foreach (var old in map.OrderBy(kv => kv.Value).Take(map.Count - cap).Select(kv => kv.Key).ToArray())
                            map.TryRemove(old, out _);

                    int uniq = map.Count;
                    if (uniq < threshold) return false;
                    map.Clear(); // Suppression must not allow unlimited accumulation.
                    if (SuppressRepeat(now, "R017", src, null, dport)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R017",
                        Description = $"Internal same-port host sweep candidate ({uniq} hosts/{window}s)",
                        SourceIp = src,
                        DestinationPort = dport,
                        Protocol = protocol,
                        Severity = SeverityLevel.High,
                        Count = uniq,
                        WindowSeconds = window
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectHostSweep error: {ex}"); }
            return false;
        }

        // ===== R018 HTTP to IP literal without Host header =====
        private static bool DetectHttpIpNoHost(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!IPAddress.TryParse(r.Source, out _) ||
                    !IPAddress.TryParse(r.Destination, out _) ||
                    r.DestinationPort is not int port || port is < 1 or > 65535 ||
                    r.Length <= 0 || r.IsQuic ||
                    !string.IsNullOrWhiteSpace(r.TlsVersion) ||
                    !string.IsNullOrWhiteSpace(r.Sni) ||
                    !(string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                bool raw = TryObservedHttpRequestLine(r.Info, out string rawMethod, out string rawUri, out bool http11);
                bool structured = IsRecognizedHttpMethod(r.HttpMethod) &&
                                  !string.IsNullOrWhiteSpace(r.HttpUri) &&
                                  r.HttpRequestHeaders != null;
                if (!raw && !structured) return false;
                if (raw && !http11) return false; // HTTP/1.0 legitimately omits Host.
                if (raw && !(r.Info!.Contains("\r\n\r\n", StringComparison.Ordinal) ||
                             r.Info.Contains("\n\n", StringComparison.Ordinal)) &&
                    !structured) return false; // Partial capture cannot prove absence.
                if (raw && !string.IsNullOrWhiteSpace(r.HttpMethod) &&
                    !string.Equals(r.HttpMethod, rawMethod, StringComparison.OrdinalIgnoreCase))
                    return false;
                if (raw && !string.IsNullOrWhiteSpace(r.HttpUri) &&
                    !string.Equals(r.HttpUri, rawUri, StringComparison.Ordinal))
                    return false;
                if (!string.IsNullOrWhiteSpace(r.HttpHost) ||
                    _httpHostHeaderRx.IsMatch(r.Info ?? "") ||
                    _httpHostHeaderRx.IsMatch(r.HttpRequestHeaders ?? "") ||
                    _httpAuthorityHeaderRx.IsMatch(r.Info ?? "") ||
                    _httpAuthorityHeaderRx.IsMatch(r.HttpRequestHeaders ?? ""))
                    return false;

                string src = r.Source!.Trim(), dst = r.Destination!.Trim();
                if (SuppressRepeat(now, "R018", src, dst, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R018",
                    Description = "Observed HTTP/1.1 request to IP literal with no Host header (review candidate)",
                    SourceIp = src,
                    DestinationIp = dst,
                    DestinationPort = port,
                    Protocol = "HTTP",
                    Severity = SeverityLevel.Medium,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectHttpIpNoHost error: {ex}"); }
            return false;
        }

        // ===== R019 Encoded/long URI (probable smuggling/tunneling) =====
        private static bool DetectHttpUriAnomaly(DateTime now, TrafficRecord r, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!IPAddress.TryParse(r.Source, out _) ||
                    !IPAddress.TryParse(r.Destination, out _) ||
                    r.DestinationPort is not int port || port is < 1 or > 65535 ||
                    r.Length <= 0 || r.IsQuic ||
                    !string.IsNullOrWhiteSpace(r.TlsVersion) ||
                    !string.IsNullOrWhiteSpace(r.Sni) ||
                    !(string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                bool raw = TryObservedHttpRequestLine(r.Info, out string rawMethod, out string rawUri, out _);
                bool structured = IsRecognizedHttpMethod(r.HttpMethod) && !string.IsNullOrWhiteSpace(r.HttpUri);
                if (!raw && !structured) return false;
                if (raw && structured &&
                    (!string.Equals(rawMethod, r.HttpMethod, StringComparison.OrdinalIgnoreCase) ||
                     !string.Equals(rawUri, r.HttpUri, StringComparison.Ordinal)))
                    return false;
                string uri = structured ? r.HttpUri! : rawUri;
                if (uri.Length == 0 || uri.Length > 65536) return false;

                int lenThresh = ScaleCount(_cfg.HttpUriLenThreshold ?? HttpUriLenThreshold, s);
                int chunkThresh = ScaleCount(_cfg.HttpUriChunkLenThreshold ?? HttpUriChunkLenThreshold, s);
                double entThresh = ScaleFloat(_cfg.HttpUriEntropyThreshold ?? HttpUriEntropyThreshold, s);
                bool tooLong = uri.Length >= lenThresh;
                bool hasChunk = false;
                if (!tooLong)
                    foreach (Match match in _b64Like.Matches(uri))
                        if (match.Length >= chunkThresh && ShannonEntropy(match.Value) >= entThresh)
                        { hasChunk = true; break; }
                if (!tooLong && !hasChunk) return false;

                string src = r.Source!.Trim(), dst = r.Destination!.Trim();
                if (SuppressRepeat(now, "R019", src, dst, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R019",
                    Description = $"Suspicious observed HTTP URI (length={uri.Length}{(hasChunk ? ", high-entropy chunk" : "")}); review context",
                    SourceIp = src,
                    DestinationIp = dst,
                    DestinationPort = port,
                    Protocol = "HTTP",
                    Severity = tooLong ? SeverityLevel.High : SeverityLevel.Medium,
                    Count = uri.Length
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectHttpUriAnomaly error: {ex}"); }
            return false;
        }

        // ===== R020 Outbound SMTP direct to Internet (port 25) =====
        private static bool DetectSmtpEgress25(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!IPAddress.TryParse(r.Source, out var srcIp) ||
                    !IsPrivateIp(r.Source) || !IsPublicLegacyEgressIp(r.Destination) ||
                    !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase) ||
                    r.DestinationPort != 25 || r.Length <= 0)
                    return false;

                bool initialSyn = r.TcpFlags.HasValue
                    ? (r.TcpFlags.Value & 0x16) == 0x02
                    : Regex.IsMatch(r.Flags ?? "", @"(?i)\bSYN\b") &&
                      !Regex.IsMatch(r.Flags ?? "", @"(?i)\b(ACK|RST|FIN)\b");
                bool observedSmtp = string.Equals(r.ApplicationService, "SMTP", StringComparison.OrdinalIgnoreCase) ||
                                    string.Equals(r.ApplicationProtocol, "SMTP", StringComparison.OrdinalIgnoreCase);
                if (!initialSyn && !observedSmtp) return false;

                string src = srcIp.ToString(), dst = IPAddress.Parse(r.Destination!).ToString();
                var allow = _cfg.SmtpAllowedSources ?? new List<string>();
                if (allow.Any(entry => IPAddress.TryParse(entry, out var allowedIp) && allowedIp.Equals(srcIp)))
                    return false;

                if (SuppressRepeat(now, "R020", src, dst, 25)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R020",
                    Description = "Direct outbound SMTP (port 25) to public Internet from unapproved private source",
                    SourceIp = src,
                    DestinationIp = dst,
                    DestinationPort = 25,
                    Protocol = "TCP",
                    Severity = SeverityLevel.High,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectSmtpEgress25 error: {ex}"); }
            return false;
        }

        // ===== R021 ICMP tunneling suspicion: attributable echo traffic only =====
        private static bool DetectIcmpTunnel(DateTime now, TrafficRecord r, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)
                    || r.Length <= 0
                    || !IPAddress.TryParse(r.Source, out _)
                    || !IPAddress.TryParse(r.Destination, out _))
                    return false;
                // When capture supplies the ICMP header, exclude errors, redirects and
                // other non-echo messages. Legacy headerless observations remain eligible.
                if (r.IcmpTypeCode is ushort typeCode
                    && typeCode is not (0x0800 or 0x0000 or 0x8000 or 0x8100))
                    return false;

                int window = _cfg.IcmpWindowSeconds ?? IcmpWindowSeconds;
                int cntThresh = ScaleCount(_cfg.IcmpPktCountThreshold ?? IcmpPktCountThreshold, s);
                long byteThresh = ScaleBytes(_cfg.IcmpTotalBytesThreshold ?? IcmpTotalBytesThreshold, s);
                BoundDictionary(_icmpWindow, 20000);
                // A large transfer to one destination must not prime an unrelated peer.
                string key = $"{r.Source}->{r.Destination}";
                var samples = _icmpWindow.GetOrAdd(key, _ => new List<(DateTime ts, int bytes)>(64));
                int count;
                long total = 0;
                lock (samples)
                {
                    var cutoff = now.AddSeconds(-window);
                    int write = 0;
                    for (int i = 0; i < samples.Count; i++)
                    {
                        var sample = samples[i];
                        if (sample.ts >= cutoff && sample.ts <= now)
                        {
                            samples[write++] = sample;
                            total += sample.bytes;
                        }
                    }
                    if (write != samples.Count) samples.RemoveRange(write, samples.Count - write);
                    samples.Add((now, r.Length));
                    total += r.Length;
                    // Bound memory independently of threshold configuration.
                    if (samples.Count > 4096)
                    {
                        int excess = samples.Count - 4096;
                        for (int i = 0; i < excess; i++) total -= samples[i].bytes;
                        samples.RemoveRange(0, excess);
                    }
                    count = samples.Count;
                    if ((count < cntThresh && total < byteThresh)
                        || (double)total / count < 24.0)
                        return false;

                    // Clear the reached window even during cooldown; a suppressed burst
                    // must not keep an old threshold armed for later traffic.
                    samples.Clear();
                }
                if (SuppressRepeat(now, "R021", r.Source!, r.Destination, null))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R021",
                    Description = $"Suspicious ICMP echo volume (pkts={count}, bytes={total}/{window}s)",
                    SourceIp = r.Source,
                    DestinationIp = r.Destination,
                    Protocol = "ICMP",
                    Severity = SeverityLevel.Medium,
                    Count = count,
                    WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectIcmpTunnel error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R022 DNS NXDOMAIN spike: observed negative responses =====
        private static bool DetectDnsNxSpike(DateTime now, TrafficRecord r, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool isDns = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                        && r.SourcePort == 53);
                if (!isDns || !r.DnsIsResponse || r.Length <= 0
                    || !IPAddress.TryParse(r.Source, out _)
                    || !IPAddress.TryParse(r.Destination, out _))
                    return false;
                // Explicit structured RCODE wins over text, including contradictions.
                bool negative = !string.IsNullOrWhiteSpace(r.DnsRcode)
                    ? string.Equals(r.DnsRcode.Trim(), "NXDOMAIN", StringComparison.OrdinalIgnoreCase)
                      || string.Equals(r.DnsRcode.Trim(), "3", StringComparison.Ordinal)
                    : Regex.IsMatch(r.Info ?? string.Empty, @"\bNXDOMAIN\b", RegexOptions.IgnoreCase);
                if (!negative) return false;

                int window = _cfg.DnsNxWindowSeconds ?? DnsNxWindowSeconds;
                int threshold = ScaleCount(_cfg.DnsNxThreshold ?? DnsNxThreshold, s);
                BoundDictionary(_nxdomain, 20000);
                // Responses travel resolver -> client; count by client and resolver,
                // not by the resolver's source alone (which aggregates all clients).
                string key = $"{r.Destination}|{r.Source}";
                var list = _nxdomain.GetOrAdd(key, _ => new List<DateTime>(threshold * 2));
                int count;
                lock (list)
                {
                    var cutoff = now.AddSeconds(-window);
                    list.RemoveAll(ts => ts < cutoff || ts > now);
                    // Same-timestamp duplicate captures cannot inflate a spike.
                    if (!list.Contains(now)) list.Add(now);
                    if (list.Count > 4096) list.RemoveRange(0, list.Count - 4096);
                    count = list.Count;
                    if (count < threshold) return false;
                    list.Clear();
                }
                if (SuppressRepeat(now, "R022", r.Destination!, r.Source, 53))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R022",
                    Description = $"NXDOMAIN response spike ({count}/{window}s)",
                    SourceIp = r.Destination,
                    DestinationIp = r.Source,
                    Protocol = "DNS",
                    Severity = SeverityLevel.High,
                    Count = count,
                    WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDnsNxSpike error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R023 TLS to public IP without SNI (three observed samples / five minutes) =====
        private static bool DetectTlsNoSniToIp(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool tls = string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                        && !string.IsNullOrWhiteSpace(r.TlsVersion));
                if (!tls || r.Length <= 0 || r.IsQuic || r.QuicVersion is not null
                    || r.QuicAlpn is not null || !IPAddress.TryParse(r.Source, out _)
                    || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                if (!string.IsNullOrWhiteSpace(r.Sni) && !IPAddress.TryParse(r.Sni, out _))
                    return false;
                if (r.DestinationPort is not int port || port is < 1 or > 65535)
                    return false;

                string key = $"R023:{r.Source}->{r.Destination}:{port}";
                BoundDictionary(_packetTimes, 20000);
                var list = _packetTimes.GetOrAdd(key, _ => new List<DateTime>(8));
                lock (list)
                {
                    var cutoff = now.AddSeconds(-300);
                    list.RemoveAll(ts => ts < cutoff || ts > now);
                    if (!list.Contains(now)) list.Add(now);
                    if (list.Count < 3) return false;
                    list.Clear();
                }
                if (SuppressRepeat(now, "R023", r.Source!, r.Destination, port))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R023",
                    Description = "Repeated TLS to a public IP without a DNS SNI name",
                    SourceIp = r.Source,
                    DestinationIp = r.Destination,
                    DestinationPort = port,
                    Protocol = "TLS",
                    Severity = SeverityLevel.Medium,
                    Count = 3,
                    WindowSeconds = 300
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R023 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R024 Rare TLS client fingerprint: structured, non-secret evidence =====
        private static bool DetectRareTlsFingerprint(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string? fp = !string.IsNullOrWhiteSpace(r.Ja4) ? r.Ja4 : r.Ja3;
                if (string.IsNullOrWhiteSpace(fp) || fp.Length > 128
                    || fp.Any(char.IsWhiteSpace) || fp.Any(char.IsControl)
                    || !IPAddress.TryParse(r.Source, out _)
                    || !IPAddress.TryParse(r.Destination, out _)
                    || r.Length <= 0 || r.IsQuic
                    || !(string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                        || !string.IsNullOrWhiteSpace(r.TlsVersion)))
                    return false;

                BoundedMerge(_ja4Counts, fp, now);
                var stat = _ja4Counts[fp];
                if (stat.Count > 3) return false;
                if (SuppressRepeat(now, "R024", r.Source!, r.Destination, r.DestinationPort))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R024",
                    // Never include raw fingerprint or untrusted capture text in alerts.
                    Description = $"Rare TLS client fingerprint (observation={stat.Count})",
                    SourceIp = r.Source,
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "TLS",
                    Severity = stat.Count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = stat.Count
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R024 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R025 TLS certificate expiry: observed and chronologically valid chain =====
        private static bool DetectTlsCertExpiry(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort != 443 || !r.CertValidTo.HasValue
                    || !IPAddress.TryParse(r.Source, out _)
                    || !IPAddress.TryParse(r.Destination, out _)
                    || r.IsQuic || r.Length <= 0
                    || !(string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                        || !string.IsNullOrWhiteSpace(r.TlsVersion)))
                    return false;
                if (r.CertValidFrom.HasValue && r.CertValidFrom.Value > r.CertValidTo.Value)
                    return false;

                double daysLeft = (r.CertValidTo.Value.ToUniversalTime() - now).TotalDays;
                if (daysLeft > 7) return false;
                if (SuppressRepeat(now, "R025", r.Source!, r.Destination, 443))
                    return false;
                bool expired = daysLeft < 0;
                det = new DetectionEvent
                {
                    RuleId = "R025",
                    Description = expired ? "TLS certificate expired" : "TLS certificate expiring within seven days",
                    SourceIp = r.Source,
                    DestinationIp = r.Destination,
                    DestinationPort = 443,
                    Protocol = "TLS",
                    Severity = expired ? SeverityLevel.High : SeverityLevel.Medium,
                    // Avoid overflow on malformed or extremely old certificate dates.
                    Count = (int)Math.Min(int.MaxValue, expired
                        ? Math.Ceiling(-daysLeft) : Math.Ceiling(daysLeft))
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R025 error: {ex.GetType().Name}"); }
            return false;
        }

        // R026-R030 use validated endpoints; leave AuthPorts unchanged for R004.
        private static readonly HashSet<int> AdminEgressPorts = new() { 21, 22, 23, 3389, 5985, 5986 };

        private static bool IsAttributablePrivateHostIp(string? value)
        {
            if (!IPAddress.TryParse(value, out var ip)) return false;
            if (ip.IsIPv4MappedToIPv6) ip = ip.MapToIPv4();
            return !IPAddress.IsLoopback(ip) && !ip.IsIPv6LinkLocal
                && !ip.IsIPv6SiteLocal && IsPrivateIp(ip.ToString());
        }

        private static bool IsInitialTcpSyn(TrafficRecord r)
        {
            if (r.TcpFlags is ushort flags)
                return (flags & 0x02) != 0 && (flags & 0x10) == 0;
            return TcpSynToken.IsMatch(r.Flags ?? string.Empty)
                && !TcpAckToken.IsMatch(r.Flags ?? string.Empty);
        }

        private static bool IsAdminServiceForPort(int port, string? service) => port switch
        {
            21 => string.Equals(service, "FTP", StringComparison.OrdinalIgnoreCase),
            22 => string.Equals(service, "SSH", StringComparison.OrdinalIgnoreCase),
            23 => string.Equals(service, "TELNET", StringComparison.OrdinalIgnoreCase),
            3389 => string.Equals(service, "RDP", StringComparison.OrdinalIgnoreCase),
            5985 or 5986 => string.Equals(service, "WINRM", StringComparison.OrdinalIgnoreCase),
            _ => false
        };

        // ===== R026 SMB/NetBIOS connection to public endpoint =====
        private static bool DetectSmbToInternet(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort is not (139 or 445) || r.Length <= 0 || r.IsQuic
                    || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || !IsAttributablePrivateHostIp(r.Source) || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                bool classified = string.Equals(r.ApplicationService, "SMB", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.ApplicationService, "NETBIOS-SSN", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.ApplicationService, "RPC", StringComparison.OrdinalIgnoreCase);
                if (!string.IsNullOrWhiteSpace(r.ApplicationService) && !classified) return false;
                if (!IsInitialTcpSyn(r) && !classified) return false;
                if (SuppressRepeat(now, "R026", r.Source!, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R026", Description = "Outbound SMB/NetBIOS connection to a public endpoint",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "TCP", Severity = SeverityLevel.High, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R026 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R027 Admin-service egress, excluding mail authentication =====
        private static bool DetectAdminEgress(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort is not int port || !AdminEgressPorts.Contains(port)
                    || r.Length <= 0 || r.IsQuic
                    || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || !IsAttributablePrivateHostIp(r.Source) || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                bool classified = IsAdminServiceForPort(port, r.ApplicationService);
                if (!string.IsNullOrWhiteSpace(r.ApplicationService) && !classified) return false;
                if (!IsInitialTcpSyn(r) && !classified) return false;
                if (SuppressRepeat(now, "R027", r.Source!, r.Destination, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R027", Description = $"Administrative service connection to public endpoint on TCP/{port}",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = port,
                    Protocol = "TCP", Severity = SeverityLevel.Medium, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R027 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R028 Direct public DNS query, not a response =====
        private static bool DetectExternalDnsDirect(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort != 53 || r.Length <= 0 || r.IsQuic || r.DnsIsResponse
                    || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname.Length > 253
                    || !IsAttributablePrivateHostIp(r.Source) || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                bool udp = string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase);
                bool dns = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase);
                bool tcp = string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);
                bool classified = string.Equals(r.ApplicationService, "DNS", StringComparison.OrdinalIgnoreCase);
                if (!(udp || dns || (tcp && classified))) return false;
                if (!string.IsNullOrWhiteSpace(r.ApplicationService) && !classified) return false;
                if (SuppressRepeat(now, "R028", r.Source!, r.Destination, 53)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R028", Description = "Direct DNS query to a public resolver candidate",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = 53,
                    Protocol = tcp ? "TCP" : "DNS", Severity = SeverityLevel.Medium, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R028 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R029 QUIC anomaly with per-flow bounded debounce =====
        private static bool DetectQuicAnomaly(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool udp = string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase);
                bool quicProtocol = string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase);
                if (!(udp || quicProtocol)
                    || !(r.IsQuic || (quicProtocol && !string.IsNullOrWhiteSpace(r.QuicVersion)))
                    || r.Length <= 0 || r.DestinationPort is not int port || port is < 1 or > 65535
                    || port is 53 or 123 or 443 || !string.IsNullOrWhiteSpace(r.QuicAlpn)
                    || !IsAttributablePrivateHostIp(r.Source) || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                BoundDictionary(_packetTimes, 20000);
                string key = $"R029:{r.Source}->{r.Destination}:{port}";
                var times = _packetTimes.GetOrAdd(key, _ => new List<DateTime>(4));
                lock (times)
                {
                    var cutoff = now.AddSeconds(-60);
                    times.RemoveAll(ts => ts < cutoff || ts > now);
                    if (!times.Contains(now)) times.Add(now);
                    if (times.Count > 3) return false;
                }
                if (SuppressRepeat(now, "R029", r.Source!, r.Destination, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R029", Description = "Observed QUIC on nonstandard UDP port without ALPN",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = port,
                    Protocol = "QUIC", Severity = SeverityLevel.Low, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R029 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R030 Distinct internal administrative SYN sweep =====
        private static bool DetectAdminLateralSweep(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort is not int port || !AdminEgressPorts.Contains(port)
                    || r.Length <= 0 || r.IsQuic
                    || !string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                    || !IsInitialTcpSyn(r) || !IsAttributablePrivateHostIp(r.Source)
                    || !IsAttributablePrivateHostIp(r.Destination)
                    || !IPAddress.TryParse(r.Source, out var srcIp)
                    || !IPAddress.TryParse(r.Destination, out var dstIp) || srcIp.Equals(dstIp))
                    return false;
                const int window = 60, threshold = 8;
                BoundDictionary(_adminSweeps, 10000);
                var map = _adminSweeps.GetOrAdd((r.Source!, port),
                    _ => new ConcurrentDictionary<string, DateTime>());
                int distinct;
                lock (map)
                {
                    var cutoff = now.AddSeconds(-window);
                    foreach (var stale in map.Where(kv => kv.Value < cutoff || kv.Value > now)
                        .Select(kv => kv.Key).ToList()) map.TryRemove(stale, out _);
                    map[r.Destination!] = now;
                    distinct = map.Count;
                    if (distinct < threshold) return false;
                    map.Clear(); // Also clear a completed window when cooldown suppresses it.
                }
                if (SuppressRepeat(now, "R030", r.Source!, null, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R030", Description = $"Internal administrative sweep across {distinct} hosts on TCP/{port}",
                    SourceIp = r.Source, DestinationPort = port, Protocol = "TCP",
                    Severity = SeverityLevel.High, Count = distinct, WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R030 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R031 DNS TXT spike: observed queries, per-client/resolver window =====
        private static bool DetectDnsTxtSpike(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool dns = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase);
                bool udp = string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase);
                bool tcp = string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase);
                if (!(dns || udp || (tcp && string.Equals(r.ApplicationService, "DNS", StringComparison.OrdinalIgnoreCase)))
                    || r.DestinationPort != 53 || r.Length <= 0 || r.IsQuic || r.DnsIsResponse
                    || !string.Equals(r.DnsQtype, "TXT", StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname.Length > 253
                    || !IPAddress.TryParse(r.Source, out _) || !IPAddress.TryParse(r.Destination, out _)
                    || (!string.IsNullOrWhiteSpace(r.ApplicationService)
                        && !string.Equals(r.ApplicationService, "DNS", StringComparison.OrdinalIgnoreCase)))
                    return false;

                const int window = 60;
                const int threshold = 15; // Preserve the existing configured detection boundary.
                BoundDictionary(_dnsTxtBySrc, 20000);
                string key = $"{r.Source}|{r.Destination}";
                var list = _dnsTxtBySrc.GetOrAdd(key, _ => new List<DateTime>(threshold * 2));
                int count;
                lock (list)
                {
                    var cutoff = now.AddSeconds(-window);
                    list.RemoveAll(ts => ts < cutoff || ts > now);
                    // Replayed or duplicated capture timestamps must not inflate volume.
                    if (!list.Contains(now)) list.Add(now);
                    if (list.Count > 4096) list.RemoveRange(0, list.Count - 4096);
                    count = list.Count;
                    if (count < threshold) return false;
                    // Clear completed bursts even when cooldown suppresses the event.
                    list.Clear();
                }
                if (SuppressRepeat(now, "R031", r.Source!, r.Destination, 53)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R031", Description = $"DNS TXT query spike ({count}/{window}s)",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = 53,
                    Protocol = "DNS", Severity = SeverityLevel.High,
                    Count = count, WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R031 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R032 HTTP User-Agent: observed requests, never expose raw header =====
        private static readonly Regex _susUa = new(@"(?i)\b(curl|wget|python-requests|Go-http-client|powershell|libwww-perl|java/\d|okhttp)\b", RegexOptions.Compiled);
        private static bool DetectSuspiciousUserAgent(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool http = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase));
                string? method = r.HttpMethod?.Trim();
                if (!http || r.Length <= 0 || r.IsQuic
                    || !IPAddress.TryParse(r.Source, out _) || !IPAddress.TryParse(r.Destination, out _)
                    || method is not ("GET" or "POST" or "PUT" or "PATCH" or "DELETE" or "HEAD" or "OPTIONS")
                    || (!string.IsNullOrWhiteSpace(r.ApplicationService)
                        && !string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase)))
                    return false;

                string ua = r.HttpUserAgent ?? string.Empty;
                bool emptyUa = string.IsNullOrWhiteSpace(ua);
                bool suspiciousUa = !emptyUa && _susUa.IsMatch(ua);
                if (!emptyUa && !suspiciousUa) return false;
                if (SuppressRepeat(now, "R032", r.Source!, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R032",
                    Description = emptyUa ? "HTTP request with empty User-Agent" : "HTTP request with automation-associated User-Agent",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = suspiciousUa ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R032 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R033 ICMP oversized observed echo packets only =====
        private static bool DetectIcmpOversized(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)
                    || r.Length < 1000 || !r.IcmpTypeCode.HasValue
                    || r.IcmpTypeCode.Value is not (0x0800 or 0x0000 or 0x8000 or 0x8100)
                    || !IPAddress.TryParse(r.Source, out _) || !IPAddress.TryParse(r.Destination, out _))
                    return false;
                if (SuppressRepeat(now, "R033", r.Source!, r.Destination, null)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R033", Description = $"Oversized ICMP echo packet ({r.Length} bytes)",
                    SourceIp = r.Source, DestinationIp = r.Destination, Protocol = "ICMP",
                    Severity = SeverityLevel.Medium, Count = r.Length
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R033 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R034 DoH: corroborated HTTP request metadata, not prose =====
        private static bool DetectDoHHeuristic(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool http = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase));
                if (!http || r.Length <= 0 || r.IsQuic || r.DestinationPort is not (443 or 8443)
                    || !IPAddress.TryParse(r.Source, out _) || !IPAddress.TryParse(r.Destination, out _)
                    || (!string.IsNullOrWhiteSpace(r.ApplicationService)
                        && !string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase)))
                    return false;
                string method = r.HttpMethod?.Trim().ToUpperInvariant() ?? string.Empty;
                string uri = r.HttpUri ?? string.Empty;
                int query = uri.IndexOf('?');
                string path = query < 0 ? uri : uri.Substring(0, query);
                if (!string.Equals(path, "/dns-query", StringComparison.OrdinalIgnoreCase)) return false;
                bool get = method == "GET" && query >= 0
                    && Regex.IsMatch(uri.Substring(query + 1), @"(?:^|&)dns=[A-Za-z0-9_-]{8,}(?:&|$)");
                bool post = method == "POST"
                    && Regex.IsMatch(r.HttpRequestHeaders ?? string.Empty,
                        @"(?im)^Content-Type:\s*application/dns-message\s*(?:;[^\r\n]*)?$");
                if (!(get || post)) return false;
                if (SuppressRepeat(now, "R034", r.Source!, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R034", Description = "Observed DNS-over-HTTPS request candidate",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = SeverityLevel.Medium, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R034 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R035 Rare SSH fingerprint: validated SSH client observation =====
        private static bool DetectRareSshFingerprint(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool ssh = string.Equals(r.Protocol, "SSH", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(r.ApplicationService, "SSH", StringComparison.OrdinalIgnoreCase));
                string? fingerprint = !string.IsNullOrWhiteSpace(r.Ja4SSH) ? r.Ja4SSH : r.Hassh;
                if (!ssh || r.Length <= 0 || r.IsQuic || string.IsNullOrWhiteSpace(fingerprint)
                    || fingerprint.Length > 128 || fingerprint.Any(char.IsWhiteSpace)
                    || fingerprint.Any(char.IsControl)
                    || !IPAddress.TryParse(r.Source, out _) || !IPAddress.TryParse(r.Destination, out _)
                    || (!string.IsNullOrWhiteSpace(r.ApplicationService)
                        && !string.Equals(r.ApplicationService, "SSH", StringComparison.OrdinalIgnoreCase)))
                    return false;

                BoundDictionary(_sshFpCounts, 5000);
                // An observation older than the latest cannot re-prime rarity.
                var stat = _sshFpCounts.AddOrUpdate(fingerprint!, _ => (1, now, now),
                    (_, prev) => now < prev.LastSeen ? prev
                        : now == prev.LastSeen ? prev
                        : (now - prev.LastSeen).TotalMinutes > 60
                            ? (1, now, now) : (Math.Min(prev.Count + 1, 4), prev.FirstSeen, now));
                if (stat.LastSeen != now || stat.Count > 3) return false;
                if (SuppressRepeat(now, "R035", r.Source!, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R035", Description = $"Rare SSH client fingerprint (observation={stat.Count})",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "SSH", Severity = stat.Count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = stat.Count
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R035 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R036 Heavy egress to single external host =====
        private static bool DetectPairExfiltration(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                // Volume is a hypothesis, not sufficient evidence to poison the service allowlist.
                if (r.Length <= 0 || !IsPrivateIp(r.Source)
                    || !IPAddress.TryParse(r.Source, out var srcIp)
                    || !IsPublicLegacyEgressIp(r.Destination)
                    || !IPAddress.TryParse(r.Destination, out var dstIp)
                    || (r.DestinationPort is int port && (port < 1 || port > 65535)))
                    return false;

                const int window = 120;
                const long thresholdBytes = 20_000_000;
                var key = (Src: srcIp.ToString(), Dst: dstIp.ToString());
                BoundDictionary(_pairBytes, 20000);
                var list = _pairBytes.GetOrAdd(key, _ => new List<(DateTime ts, int bytes)>(64));
                lock (list)
                {
                    // Reject out-of-order observations; dedupe an indistinguishable retransmit.
                    if (list.Count > 0 && now < list[^1].ts) return false;
                    if (list.Count > 0 && now == list[^1].ts && r.Length == list[^1].bytes)
                        return false;
                    list.RemoveAll(t => t.ts < now.AddSeconds(-window));
                    list.Add((now, r.Length));
                    if (list.Count > 10000) list.RemoveRange(0, list.Count - 10000);

                    long total = 0;
                    foreach (var observation in list) total += observation.bytes;
                    if (total < thresholdBytes) return false;

                    // A completed suppressed window must not prime the next window.
                    list.Clear();
                    if (SuppressRepeat(now, "R036", key.Src, key.Dst, r.DestinationPort))
                        return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R036",
                        Description = $"High-volume outbound transfer to a single public host ({total} bytes/{window}s)",
                        SourceIp = key.Src,
                        DestinationIp = key.Dst,
                        DestinationPort = r.DestinationPort,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.Critical,
                        Count = (int)Math.Min(total, int.MaxValue),
                        WindowSeconds = window
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R036 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R037 JA4 drift per SNI =====
        private static bool DetectJa4DriftPerSni(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.Length <= 0 || !IPAddress.TryParse(r.Source, out _)
                    || !IsPublicLegacyEgressIp(r.Destination)
                    || !(r.IsQuic || string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase)
                         || string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase)))
                    return false;

                var sni = r.Sni?.Trim().TrimEnd('.').ToLowerInvariant();
                var ja4 = r.Ja4?.Trim();
                if (string.IsNullOrEmpty(sni) || string.IsNullOrEmpty(ja4)
                    || !Regex.IsMatch(sni, @"\A(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\z",
                        RegexOptions.CultureInvariant)
                    || !Regex.IsMatch(ja4, @"\A[A-Za-z0-9_-]{8,128}\z", RegexOptions.CultureInvariant))
                    return false;

                const int windowSeconds = 3600;
                const int minDistinct = 3, minTotal = 5, maxTotalForRare = 50;
                BoundDictionary(_sniJa4Drift, 5000);
                var list = _sniJa4Drift.GetOrAdd(sni, _ => new List<(DateTime Ts, string Fingerprint)>());
                lock (list)
                {
                    if (list.Count > 0 && now < list[^1].Ts) return false;
                    list.RemoveAll(x => x.Ts < now.AddSeconds(-windowSeconds));
                    // Same timestamp + same fingerprint cannot manufacture repeated handshakes.
                    if (list.Any(x => x.Ts == now && x.Fingerprint == ja4)) return false;
                    list.Add((now, ja4));
                    if (list.Count > 64) list.RemoveRange(0, list.Count - 64);
                    int total = list.Count;
                    int distinct = list.Select(x => x.Fingerprint).Distinct(StringComparer.Ordinal).Count();
                    if (distinct < minDistinct || total < minTotal || total > maxTotalForRare)
                        return false;

                    list.Clear();
                    if (SuppressRepeat(now, "R037", NS(r.Source), r.Destination, r.DestinationPort))
                        return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R037",
                        // Neither SNI nor JA4 is copied into alert text.
                        Description = $"JA4 diversity changed for a low-volume TLS destination (distinct={distinct}, observations={total})",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = NP(r.Protocol),
                        Severity = distinct >= 5 ? SeverityLevel.High : SeverityLevel.Medium,
                        Count = distinct,
                        WindowSeconds = windowSeconds
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R037 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== R038 Encrypted DNS bootstrap (corroborated DoH + QUIC) =====
        private static bool DetectEncryptedDnsBootstrap(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.Length <= 0 || !IsPrivateIp(r.Source)
                    || !IPAddress.TryParse(r.Source, out var srcIp)
                    || !IsPublicLegacyEgressIp(r.Destination))
                    return false;

                const int windowSeconds = 300, dohThreshold = 10, quicThreshold = 3;
                const double sniEntropyThreshold = 3.5;
                string src = srcIp.ToString();
                bool isDoH = IsDoHLike(r);
                bool isQuicHiEntropy = r.DestinationPort == 443
                    && (r.IsQuic || string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase))
                    && !string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                    && !string.IsNullOrWhiteSpace(r.Sni)
                    && Regex.IsMatch(r.Sni!, @"\A[A-Za-z0-9.-]{8,253}\z", RegexOptions.CultureInvariant)
                    && ShannonEntropy(r.Sni!) >= sniEntropyThreshold;
                if (!isDoH && !isQuicHiEntropy) return false;

                // One timestamp is one observation in this coarse replay/capture model.
                if (isDoH)
                {
                    var list = _dohBySrc.GetOrAdd(src, _ => new List<DateTime>());
                    if (!AppendDistinctWindowTime(list, now, windowSeconds)) return false;
                    BoundDictionary(_dohBySrc, 10000);
                }
                if (isQuicHiEntropy)
                {
                    var list = _quicHiEntropyBySrc.GetOrAdd(src, _ => new List<DateTime>());
                    if (!AppendDistinctWindowTime(list, now, windowSeconds)) return false;
                    BoundDictionary(_quicHiEntropyBySrc, 10000);
                }

                int dohCount = 0, quicCount = 0;
                if (_dohBySrc.TryGetValue(src, out var doh))
                    lock (doh) { doh.RemoveAll(t => t < now.AddSeconds(-windowSeconds)); dohCount = doh.Count; }
                if (_quicHiEntropyBySrc.TryGetValue(src, out var quic))
                    lock (quic) { quic.RemoveAll(t => t < now.AddSeconds(-windowSeconds)); quicCount = quic.Count; }
                if (dohCount < dohThreshold || quicCount < quicThreshold) return false;

                // Clear both completed windows, including a suppressed detection.
                if (_dohBySrc.TryGetValue(src, out doh)) lock (doh) doh.Clear();
                if (_quicHiEntropyBySrc.TryGetValue(src, out quic)) lock (quic) quic.Clear();
                if (SuppressRepeat(now, "R038", src, r.Destination, r.DestinationPort)) return false;

                int score = dohCount * 2 + quicCount;
                det = new DetectionEvent
                {
                    RuleId = "R038",
                    Description = $"Correlated encrypted-DNS bootstrap pattern (DoH={dohCount}, QUIC={quicCount}, window={windowSeconds}s)",
                    SourceIp = src,
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = score >= 30 ? SeverityLevel.High : SeverityLevel.Medium,
                    Count = score,
                    WindowSeconds = windowSeconds
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R038 error: {ex.GetType().Name}"); }
            return false;
        }

        private static bool AppendDistinctWindowTime(List<DateTime> list, DateTime now, int windowSeconds)
        {
            lock (list)
            {
                if (list.Count > 0 && now <= list[^1]) return false;
                list.RemoveAll(t => t < now.AddSeconds(-windowSeconds));
                list.Add(now);
                if (list.Count > 256) list.RemoveRange(0, list.Count - 256);
                return true;
            }
        }

        // R038 requires wire-structured DoH evidence; arbitrary prose in Info
        // or request headers cannot establish the method and request target.
        private static bool IsDoHLike(TrafficRecord r)
        {
            if (r.DestinationPort != 443 || r.IsQuic
                || !(string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                     || string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase))
                || (r.ApplicationService != null
                    && !string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(r.ApplicationService, "HTTPS", StringComparison.OrdinalIgnoreCase)
                    && !string.Equals(r.ApplicationService, "DOH", StringComparison.OrdinalIgnoreCase)))
                return false;
            var uri = r.HttpUri;
            if (string.IsNullOrWhiteSpace(uri)
                || !Regex.IsMatch(uri, @"\A/dns-query(?:\?|$)", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant))
                return false;
            if (string.Equals(r.HttpMethod, "GET", StringComparison.OrdinalIgnoreCase))
                return Regex.IsMatch(uri, @"[?&]dns=[A-Za-z0-9_-]{8,}(?:&|$)", RegexOptions.CultureInvariant);
            if (string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase))
                return Regex.IsMatch(r.HttpRequestHeaders ?? string.Empty,
                    @"(?im)^Content-Type\s*:\s*application/dns-message\s*(?:;[^\r\n]*)?$",
                    RegexOptions.CultureInvariant);
            return false;
        }

        // ===== R039 ASN novelty on explicitly sensitive outbound assets =====
        private static bool DetectAsnNoveltySensitive(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.Length <= 0 || !IsSensitiveVlanFlow(r)
                    || !IsPrivateIp(r.Source) || !IPAddress.TryParse(r.Source, out var sourceIp)
                    || !IsPublicLegacyEgressIp(r.Destination))
                    return false;
                var match = Regex.Match(r.WhoisASN ?? string.Empty,
                    @"\A\s*AS(?<number>[1-9][0-9]{0,9})(?:\s|$)",
                    RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                if (!match.Success || !uint.TryParse(match.Groups["number"].Value, out var asnNumber))
                    return false;
                string asn = "AS" + asnNumber;
                string key = sourceIp + "|" + asn;
                if (_asnSeenOnSensitive.TryGetValue(key, out var prior) && now < prior)
                    return false;

                var cutoff = now.AddDays(-7);
                foreach (var kv in _asnSeenAnywhere.Where(x => x.Value.LastSeen < cutoff).Take(100).ToList())
                    _asnSeenAnywhere.TryRemove(kv.Key, out _);
                foreach (var kv in _asnSeenOnSensitive.Where(x => x.Value < cutoff).Take(100).ToList())
                    _asnSeenOnSensitive.TryRemove(kv.Key, out _);
                BoundDictionary(_asnSeenAnywhere, 20000);
                BoundDictionary(_asnSeenOnSensitive, 5000);

                bool seenPreviously = _asnSeenAnywhere.TryGetValue(asn, out var prev)
                    && prev.FirstSeen < now.AddMinutes(-10);
                if (!_asnSeenOnSensitive.TryAdd(key, now)) return false;
                _asnSeenAnywhere.AddOrUpdate(asn, _ => (now, now),
                    (_, old) => (old.FirstSeen, now > old.LastSeen ? now : old.LastSeen));

                if (SuppressRepeat(now, "R039", sourceIp.ToString(), r.Destination, r.DestinationPort))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R039",
                    Description = $"Previously unobserved destination ASN {asn} for an explicitly sensitive source",
                    SourceIp = sourceIp.ToString(),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = seenPreviously ? SeverityLevel.Medium : SeverityLevel.High,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R039 error: {ex.GetType().Name}"); }
            return false;
        }

        // ===== Local flow stat for R040 =====
        private sealed class FlowStat
        {
            public DateTime First;
            public DateTime Last;
            public long Bytes;
            public int Count;
        }

        // R040: Long-lived, low-throughput encrypted sessions
        private static readonly ConcurrentDictionary<(string Src, string Dst, int? Port), FlowStat> _encFlow =
            new();

        // R041-R043 state moved to RuleEngine.R041-R045.cs.

        // R048: Alternate DoH pattern rate-limiting
        private static readonly ConcurrentDictionary<string, List<DateTime>> _altDohSeenBySrc =
            new(StringComparer.Ordinal);

        // ===== R040: Long-lived, low-throughput encrypted session =====
        private static bool DetectEncryptedLowAndSlow(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool encryptedLike = string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase)
                    || (r.IsQuic && !string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase));
                if (!encryptedLike || r.Length <= 0
                    || !IsPrivateIp(r.Source) || !IPAddress.TryParse(r.Source, out var srcIp)
                    || !IsPublicLegacyEgressIp(r.Destination)
                    || !IPAddress.TryParse(r.Destination, out var dstIp)
                    || r.DestinationPort is not int port || port < 1 || port > 65535)
                    return false;

                var key = (Src: srcIp.ToString(), Dst: dstIp.ToString(), Port: (int?)port);
                BoundDictionary(_encFlow, 10000);
                var fs = _encFlow.GetOrAdd(key, _ => new FlowStat
                {
                    First = now, Last = now, Bytes = 0, Count = 0
                });
                lock (fs)
                {
                    if (fs.Count > 0 && now <= fs.Last) return false;
                    // An idle gap or stale session is a new flow, not 15 minutes
                    // of uninterrupted low-throughput encrypted activity.
                    if (fs.Count > 0 && ((now - fs.Last).TotalSeconds > 300
                        || (now - fs.First).TotalHours > 24))
                    {
                        fs.First = now;
                        fs.Bytes = 0;
                        fs.Count = 0;
                    }
                    fs.Last = now;
                    if (r.Length > 300_000 || fs.Bytes + r.Length > 300_000)
                    {
                        fs.First = now;
                        fs.Bytes = 0;
                        fs.Count = 0;
                        return false;
                    }
                    fs.Bytes += r.Length;
                    fs.Count++;

                    double lifetime = (now - fs.First).TotalSeconds;
                    if (lifetime < 900 || fs.Count < 12) return false;
                    _encFlow.TryRemove(key, out _);
                    if (SuppressRepeat(now, "R040", key.Src, key.Dst, key.Port))
                        return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R040",
                        Description = $"Long-lived low-throughput encrypted flow (duration≈{lifetime / 60:F1}m, observations={fs.Count}, bytes={fs.Bytes})",
                        SourceIp = key.Src,
                        DestinationIp = key.Dst,
                        DestinationPort = key.Port,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = fs.Count,
                        WindowSeconds = (int)Math.Round(lifetime)
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R040 error: {ex.GetType().Name}"); }
            return false;
        }

        // R041-R045 implementations and state moved to RuleEngine.R041-R045.cs.

        // ===== R046: Unauthorized VPN protocol egress =====
        private static bool DetectUnauthorizedVpnEgress(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!IsPrivateIp(r.Source) || IsPrivateIp(r.Destination))
                    return false;

                bool udp = string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase);
                if (!udp) return false;

                if (r.DestinationPort is not int dp) return false;

                // Conservative list of UDP VPN/tunnel ports (IPsec/L2TP/OpenVPN/WireGuard/etc.)
                bool vpnPort = dp is 500 or 4500 or 1701 or 1194 or 51820 or 51821 or 443;

                if (!vpnPort) return false;

                // Light per-source debounce using shared _packetTimes
                var key = $"R046:{NS(r.Source)}";
                var list = _packetTimes.GetOrAdd(key, _ => new List<DateTime>(8));
                lock (list)
                {
                    list.Add(now);
                    if (TrimAndCount(list, now, 60) > 3)
                        return false;
                }

                if (SuppressRepeat(now, "R046", NS(r.Source), r.Destination, dp))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R046",
                    Description = $"Possible unauthorized VPN egress (UDP/{dp}) to Internet",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = dp,
                    Protocol = "UDP",
                    Severity = SeverityLevel.Medium,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R046 error: {ex}");
                return false;
            }
        }

        // ===== R047: HTTP Basic-Auth to IP literal =====
        private static bool DetectHttpBasicAuthToIp(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string info = r.Info ?? string.Empty;
                bool httpLike =
                    string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ||
                    r.HttpMethod is not null ||
                    info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase);
                if (!httpLike) return false;

                if (string.IsNullOrWhiteSpace(r.Destination) || !IPAddress.TryParse(r.Destination, out _))
                    return false;

                string headers = r.HttpRequestHeaders ?? info;
                if (!_authBasicRx.IsMatch(headers))
                    return false;

                if (SuppressRepeat(now, "R047", NS(r.Source), r.Destination, r.DestinationPort))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R047",
                    Description = "HTTP Basic-Auth used against IP literal (credential exposure risk)",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTP",
                    Severity = SeverityLevel.High,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R047 error: {ex}");
                return false;
            }
        }

        // ===== R048: Alternate DoH patterns (dns= param / application/dns-json) =====
        private static bool DetectAlternateDoHPatterns(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string info = r.Info ?? string.Empty;
                bool httpLike =
                    string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ||
                    r.HttpMethod is not null ||
                    info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase);
                if (!httpLike) return false;

                var firstLine = info.Split('\n').FirstOrDefault() ?? string.Empty;
                var parts = firstLine.Split(' ');
                string method = parts.Length > 0 ? parts[0] : string.Empty;
                string uri = r.HttpUri ?? (parts.Length > 1 ? parts[1] : string.Empty);
                string headers = r.HttpRequestHeaders ?? info;

                string host;
                var mHost = _httpHostCaptureRx.Match(headers);
                host = mHost.Success ? mHost.Groups["host"].Value : string.Empty;

                bool altPattern =
                    _dohDnsParamRx.IsMatch(uri) ||
                    headers.IndexOf("application/dns-json", StringComparison.OrdinalIgnoreCase) >= 0;

                bool likelyProvider =
                    (!string.IsNullOrWhiteSpace(host) &&
                     (host.IndexOf("dns.google", StringComparison.OrdinalIgnoreCase) >= 0 ||
                      host.IndexOf("cloudflare-dns.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                      host.IndexOf("mozilla.cloudflare-dns.com", StringComparison.OrdinalIgnoreCase) >= 0 ||
                      host.StartsWith("doh.", StringComparison.OrdinalIgnoreCase)))
                    ||
                    (!string.IsNullOrWhiteSpace(r.Destination) &&
                     (r.Destination == "1.1.1.1" ||
                      r.Destination == "8.8.8.8" ||
                      r.Destination == "9.9.9.9"));

                if (!(string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) ||
                      string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase)))
                    return false;

                if (!(altPattern && likelyProvider))
                    return false;

                var list = _altDohSeenBySrc.GetOrAdd(NS(r.Source), _ => new List<DateTime>(8));
                lock (list)
                {
                    list.Add(now);
                    TrimAndCount(list, now, 120);
                }

                if (SuppressRepeat(now, "R048", NS(r.Source), r.Destination, r.DestinationPort))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R048",
                    Description = $"Alternate DoH pattern detected (host={host}, uri={uri})",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTP",
                    Severity = SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R048 error: {ex}");
                return false;
            }
        }

        // ===== R049: Suspicious SNI shape (entropy/length/single-label) =====
        private static bool DetectSuspiciousSniShape(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string? sni = r.Sni;
                if (string.IsNullOrWhiteSpace(sni)) return false;
                if (IsPrivateIp(r.Destination)) return false;

                var labels = sni.Split('.', StringSplitOptions.RemoveEmptyEntries);
                double ent = ShannonEntropy(sni);
                double avgLabelLen = labels.Length > 0 ? labels.Average(l => l.Length) : 0.0;

                bool singleLabel = labels.Length <= 1;
                bool tooLong = sni.Length >= 40;
                bool highEntropy = ent >= 3.7;
                bool manyHyphens = labels.Any(l => l.Count(c => c == '-') >= 3);

                if (!(singleLabel || tooLong || highEntropy || manyHyphens))
                    return false;

                if (SuppressRepeat(now, "R049", NS(r.Source), r.Destination, r.DestinationPort))
                    return false;

                var sev = (highEntropy || tooLong) ? SeverityLevel.Medium : SeverityLevel.Low;

                det = new DetectionEvent
                {
                    RuleId = "R049",
                    Description = $"Suspicious SNI '{sni}' (len={sni.Length}, H={ent:F2}, avgLbl={avgLabelLen:F1}, labels={labels.Length})",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = sev,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R049 error: {ex}");
                return false;
            }
        }

        private static bool IsSensitiveVlanFlow(TrafficRecord r)
        {
            // Primary: explicit NetworkType tags from enrichment
            if (!string.IsNullOrWhiteSpace(r.NetworkType))
            {
                var nt = r.NetworkType.Trim();
                if (nt.Equals("Sensitive", StringComparison.OrdinalIgnoreCase)
                    || nt.Equals("Server", StringComparison.OrdinalIgnoreCase)
                    || nt.Equals("DC", StringComparison.OrdinalIgnoreCase)
                    || nt.Equals("OT", StringComparison.OrdinalIgnoreCase)
                    || nt.Equals("PCI", StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            // Fallback heuristic: external -> internal private (likely ingress into a sensitive VLAN)
            if (!string.IsNullOrWhiteSpace(r.Source) && !string.IsNullOrWhiteSpace(r.Destination))
            {
                bool srcExternal = !IsPrivateIp(r.Source);
                bool dstInternal = IsPrivateIp(r.Destination);
                if (srcExternal && dstInternal)
                    return true;
            }

            return false;
        }
    }
}
