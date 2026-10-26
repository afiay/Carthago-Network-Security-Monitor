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
                total += _floodStats.Count;
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
        private static readonly ConcurrentDictionary<string, List<DateTime>> _packetTimes = new(StringComparer.Ordinal);                        // R002 (+ light rate-limiters, R023, R029, R038)
        private static readonly ConcurrentDictionary<string, (int Syn, int Ack, long Bytes, DateTime Ts)> _floodStats = new(StringComparer.Ordinal); // R002
        private static readonly ConcurrentDictionary<(string Src, string Dst, int DstPort), List<DateTime>> _authAttempts = new();
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dnsQueries = new(StringComparer.Ordinal);   // R006
        private static readonly ConcurrentDictionary<(string Src, string Dst), List<(DateTime ts, int bytes)>> _beaconing = new();        // R007
        private static readonly ConcurrentDictionary<string, List<(DateTime ts, int bytes)>> _exfilBytes = new(StringComparer.Ordinal); // R008
        private static readonly ConcurrentDictionary<string, string> _arpTable = new(StringComparer.Ordinal);             // R015
        private static readonly ConcurrentDictionary<string, List<DateTime>> _dhcpActivity = new(StringComparer.Ordinal); // R011 key "DHCP"

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
        private static readonly ConcurrentDictionary<(string Src, int Port), ConcurrentDictionary<string, DateTime>> _hostSweeps = new(); // R017
        private static readonly Regex _b64Like = new(@"[A-Za-z0-9+/_-]{80,}={0,2}", RegexOptions.Compiled); // R019
        private static readonly ConcurrentDictionary<string, List<DateTime>> _icmpTimes = new(StringComparer.Ordinal); // R021
        private static readonly ConcurrentDictionary<string, List<(DateTime ts, int bytes)>> _icmpWindow = new(StringComparer.Ordinal); // R021 per-source samples for windowed ICMP analysis
        private static readonly ConcurrentDictionary<string, long> _icmpBytes = new(StringComparer.Ordinal);           // R021
        private static readonly ConcurrentDictionary<string, List<DateTime>> _nxdomain = new(StringComparer.Ordinal);  // R022

        // ===== ARP parsing hints =====
        private static readonly Regex _arpIsAtRegex = new(
            @"(?i)\b(is-at|reply)\b.*?(?<ip>\d{1,3}(?:\.\d{1,3}){3}).*?(?<mac>(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2})",
            RegexOptions.Compiled);

        // ===== HTTP header parsing aids =====
        private static readonly Regex _httpHostHeaderRx =
            new(@"(?im)^\s*Host\s*:\s*\S+", RegexOptions.Compiled);

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
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, (int Count, DateTime LastSeen)>> _sniJa4Drift =
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
                bool syn = record.Flags?.Contains("SYN") == true;
                bool ack = record.Flags?.Contains("ACK") == true;
                if (!syn || ack) return false;

                if (record.DestinationPort is not int dport) return false;

                int window = _cfg.PortScanWindowSeconds ?? PortScanWindowSeconds;
                int threshold = ScaleCount(_cfg.PortScanThreshold ?? PortScanThreshold, s);

                var map = _srcDstToPorts.GetOrAdd((src, record.Destination), _ => new ConcurrentDictionary<int, DateTime>());
                map[dport] = now;

                // Basic per-(src,dst) bounding to avoid pathological scans
                const int maxPortsPerPair = 4096;
                if (map.Count > maxPortsPerPair)
                {
                    var cutoffHard = now.AddSeconds(-window);
                    foreach (var k in map.Where(kv => kv.Value < cutoffHard).Select(kv => kv.Key).ToList())
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
                foreach (var k in map.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
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
                BoundDictionary(_packetTimes, 50000);
                BoundDictionary(_floodStats, 50000);

                if (record.Source is not { Length: > 0 } src
                    || string.IsNullOrWhiteSpace(record.Destination)) return false;
                // SYN volume toward one service must not be manufactured by
                // aggregating unrelated destinations from a busy scanner.
                var floodKey = $"R002:{src}->{record.Destination}";

                var window = _cfg.FloodWindowSeconds ?? FloodWindowSeconds;
                var pktThreshold = ScaleCount(_cfg.FloodThreshold ?? FloodThreshold, s);
                var byteThreshold = ScaleBytes(_cfg.FloodByteThreshold ?? FloodByteThreshold, s);
                var synAckRatioThresh = ScaleFloat(_cfg.SynAckRatioThreshold ?? SynAckRatioThreshold, s);

                var list = _packetTimes.GetOrAdd(floodKey, _ => new List<DateTime>(capacity: Math.Max(pktThreshold * 2, 32)));
                int pktCount;
                lock (list)
                {
                    list.Add(now);
                    pktCount = TrimAndCount(list, now, window);
                }

                bool syn = record.Flags?.Contains("SYN") == true;
                bool ack = record.Flags?.Contains("ACK") == true;

                var stats = _floodStats.AddOrUpdate(
                    floodKey,
                    _ => (Syn: syn ? 1 : 0, Ack: ack ? 1 : 0, Bytes: (long)Math.Max(0, record.Length), Ts: now),
                    (_, prev) => now >= prev.Ts && now - prev.Ts <= TimeSpan.FromSeconds(window)
                        ? (prev.Syn + (syn ? 1 : 0), prev.Ack + (ack ? 1 : 0),
                            prev.Bytes + Math.Max(0, record.Length), now)
                        : (Syn: syn ? 1 : 0, Ack: ack ? 1 : 0, Bytes: (long)Math.Max(0, record.Length), Ts: now)
                );

                if (pktCount >= pktThreshold && stats.Bytes >= byteThreshold)
                {
                    double synAckRatio = (stats.Ack > 0) ? (double)stats.Syn / stats.Ack : stats.Syn;
                    if (synAckRatio >= synAckRatioThresh)
                    {
                        if (SuppressRepeat(now, "R002", src, record.Destination, record.DestinationPort)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R002",
                            Description = $"Possible flood/DoS from {src} (pkts={pktCount}, bytes={stats.Bytes}/{window}s, SYN/ACK={synAckRatio:F1})",
                            SourceIp = src,
                            DestinationIp = record.Destination,
                            DestinationPort = record.DestinationPort,
                            Protocol = NP(record.Protocol),
                            Severity = SeverityLevel.Critical,
                            Count = pktCount,
                            WindowSeconds = window
                        };

                        lock (list) list.Clear();
                        _floodStats[floodKey] = (0, 0, 0, now);
                        return true;
                    }
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

                var host = record.Destination.ToLowerInvariant();
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

                string proto = record.ApplicationService?.ToUpperInvariant()
                               ?? record.Protocol?.ToUpperInvariant()
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

        // ===== R006 DNS Anomalies (entropy/length) =====
        private static bool DetectDnsAnomaly(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                bool isDns = string.Equals(record.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                             || (string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) && record.DestinationPort == 53);
                if (!isDns || record.Source is not { Length: > 0 } src) return false;

                BoundDictionary(_dnsQueries, 20000);

                var window = _cfg.DnsWindowSeconds ?? DnsWindowSeconds;
                var threshold = ScaleCount(_cfg.DnsThreshold ?? DnsThreshold, s);

                var entropyThresh = ScaleFloat(_cfg.DnsEntropyThreshold ?? DnsEntropyThreshold, s);
                var avgLabelLenThresh = ScaleFloat(_cfg.DnsAvgLabelLenThreshold ?? DnsAvgLabelLenThreshold, s);
                var queryLenThresh = ScaleCount(_cfg.DnsQueryLenThreshold ?? DnsQueryLenThreshold, s);

                var list = _dnsQueries.GetOrAdd(src, _ => new List<DateTime>(capacity: Math.Max(threshold * 2, 32)));
                bool suspiciousContent = false;
                lock (list)
                {
                    list.Add(now);
                    TrimAndCount(list, now, window);

                    var q = record.DnsQname;
                    if (!string.IsNullOrWhiteSpace(q))
                    {
                        var labels = q.Split('.', StringSplitOptions.RemoveEmptyEntries);
                        double avgLen = labels.Length > 0 ? labels.Average(l => l.Length) : 0;
                        var longestLabel = labels.OrderByDescending(l => l.Length).FirstOrDefault() ?? string.Empty;
                        var ent = ShannonEntropy(longestLabel);

                        // Whole-hostname entropy is high even for ordinary dotted DNS names.
                        // Require unusually long, encoded-looking labels before calling it tunneling.
                        if ((longestLabel.Length >= Math.Max(20, avgLabelLenThresh) && ent > entropyThresh)
                            || (q.Length > queryLenThresh * 2 && avgLen > avgLabelLenThresh))
                            suspiciousContent = true;
                    }

                    // Burst volume alone is not evidence of DNS tunneling; a high-severity
                    // tunneling hypothesis also requires suspicious query-name telemetry.
                    if (list.Count >= threshold)
                    {
                        if (SuppressRepeat(now, "R006", src, record.Destination, record.DestinationPort)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R006",
                            Description = suspiciousContent
                                ? $"Possible DNS tunneling from {src} ({list.Count}/{window}s, high-entropy/long query)"
                                : $"Elevated DNS request volume from {src} ({list.Count}/{window}s; query content not corroborated)",
                            SourceIp = src,
                            DestinationIp = record.Destination,
                            Protocol = NP(record.Protocol),
                            Severity = suspiciousContent ? SeverityLevel.High : SeverityLevel.Medium,
                            Count = list.Count,
                            WindowSeconds = window
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDnsAnomaly error: {ex}"); }
            return false;
        }

        // ===== R007 C2 Beaconing (tightened) =====
        private static bool DetectBeaconing(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                BoundDictionary(_beaconing, 20000);

                if (record.Source is not { Length: > 0 } src || record.Destination is not { Length: > 0 } dst) return false;
                if (IsPrivateIp(dst)) return false; // focus on Internet beacons; remove if you want internal C2 too

                var key = (Src: src, Dst: dst);
                var list = _beaconing.GetOrAdd(key, _ => new List<(DateTime ts, int bytes)>(capacity: 64));

                lock (list)
                {
                    list.Add((now, Math.Max(0, record.Length)));
                    int minSamples = ScaleCount(_cfg.BeaconMinSamples ?? BeaconMinSamples, s);
                    if (list.Count < minSamples) return false;

                    var elapsed = (list[^1].ts - list[0].ts).TotalSeconds;
                    int minObs = ScaleCount(_cfg.BeaconMinObservationSeconds ?? BeaconMinObservationSeconds, s);
                    if (elapsed < minObs) return false;

                    // intervals + jitter
                    var intervals = new List<double>(list.Count - 1);
                    for (int i = 1; i < list.Count; i++) intervals.Add((list[i].ts - list[i - 1].ts).TotalSeconds);
                    double avg = intervals.Average();
                    double variance = intervals.Select(x => (x - avg) * (x - avg)).Sum();
                    if (variance <= 0) return false;
                    double stddev = Math.Sqrt(variance / intervals.Count);
                    double frac = _cfg.BeaconStdDevFraction ?? BeaconStdDevFraction;

                    bool lowJitter = stddev < Math.Max(0.5, avg * frac); // add absolute floor (0.5s) to avoid μ≈0.2s noise
                    bool periodic = AutocorrSpike(intervals, _cfg.BeaconAutocorrLags ?? BeaconAutocorrLags);

                    // small keep-alives are more beacon-like
                    double avgBytes = list.Average(t => t.bytes);
                    bool smallPayload = avgBytes <= 600; // tweak if needed

                    if (lowJitter && periodic && smallPayload)
                    {
                        if (SuppressRepeat(now, "R007", src, dst, record.DestinationPort)) return false;

                        var sev = avg >= 30 && avg <= 600 ? SeverityLevel.High : SeverityLevel.Medium;

                        detection = new DetectionEvent
                        {
                            RuleId = "R007",
                            Description = $"Possible C2 beacon {src} → {dst} (μ={avg:F1}s, σ={stddev:F2}, avgB={avgBytes:F0}, autocorr=yes)",
                            SourceIp = src,
                            DestinationIp = dst,
                            Protocol = NP(record.Protocol),
                            Severity = sev,
                            Count = list.Count,
                            WindowSeconds = (int)Math.Round(elapsed)
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectBeaconing error: {ex}"); }
            return false;
        }

        // ===== R008 Exfiltration (per-src to Internet) =====
        private static bool DetectExfiltration(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                BoundDictionary(_exfilBytes, 20000);

                if (record.Source is not { Length: > 0 } src || record.Length <= 0) return false;
                if (IsPrivateIp(record.Destination)) return false;

                var window = _cfg.ExfilWindowSeconds ?? ExfilWindowSeconds;
                var thresholdBytes = ScaleBytes(_cfg.ExfilThresholdBytes ?? ExfilThresholdBytes, s);

                var list = _exfilBytes.GetOrAdd(src, _ => new List<(DateTime, int)>(capacity: 32));
                lock (list)
                {
                    list.Add((now, record.Length));
                    var cutoff = now.AddSeconds(-window);
                    list.RemoveAll(t => t.ts < cutoff);

                    int totalBytes = 0;
                    for (int i = 0; i < list.Count; i++) totalBytes += list[i].bytes;
                    if (totalBytes >= thresholdBytes)
                    {
                        if (SuppressRepeat(now, "R008", src, record.Destination, record.DestinationPort)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R008",
                            Description = $"Possible data exfiltration from {src} ({totalBytes} bytes / {window}s)",
                            SourceIp = src,
                            DestinationIp = record.Destination,
                            Protocol = NP(record.Protocol),
                            Severity = SeverityLevel.Critical,
                            Count = totalBytes,
                            WindowSeconds = window
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectExfiltration error: {ex}"); }
            return false;
        }

        // ===== R009 VPN/Proxy =====
        private static bool DetectVpnProxy(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if ((record.IsVpn == true) || (record.IsProxy == true))
                {
                    if (SuppressRepeat(now, "R009", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R009",
                        Description = $"Traffic from VPN/Proxy detected: {NS(record.Source)}",
                        SourceIp = NS(record.Source),
                        DestinationIp = record.Destination,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = 1,
                        WindowSeconds = 0
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectVpnProxy error: {ex}"); }
            return false;
        }

        // ===== R010 GeoIP =====
        private static bool DetectBlacklistedCountry(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!string.IsNullOrEmpty(record.WhoisCountry) && _blacklistedCountries.Contains(record.WhoisCountry))
                {
                    if (SuppressRepeat(now, "R010", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R010",
                        Description = $"Traffic to/from blacklisted country {record.WhoisCountry}",
                        SourceIp = NS(record.Source),
                        DestinationIp = record.Destination,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.High,
                        Count = 1,
                        WindowSeconds = 0
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectBlacklistedCountry error: {ex}"); }
            return false;
        }

        // ===== R011 DHCP Abuse =====
        private static bool DetectDhcpAbuse(DateTime now, TrafficRecord record, Sensitivity s, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                bool isDhcp =
                    (string.Equals(record.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) &&
                     ((record.SourcePort == 68 && record.DestinationPort == 67) ||
                      (record.SourcePort == 67 && record.DestinationPort == 68)))
                    || string.Equals(record.ApplicationService, "DHCP", StringComparison.OrdinalIgnoreCase);

                if (!isDhcp) return false;

                BoundDictionary(_dhcpActivity, 128);

                var window = _cfg.DhcpWindowSeconds ?? DhcpWindowSeconds;
                var threshold = ScaleCount(_cfg.DhcpThreshold ?? DhcpThreshold, s);

                var list = _dhcpActivity.GetOrAdd("DHCP", _ => new List<DateTime>(capacity: Math.Max(threshold * 2, 64)));
                lock (list)
                {
                    list.Add(now);
                    int count = TrimAndCount(list, now, window);

                    if (count >= threshold)
                    {
                        if (SuppressRepeat(now, "R011", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R011",
                            Description = $"Suspicious DHCP activity — {count}/{window}s",
                            SourceIp = NS(record.Source),
                            DestinationIp = record.Destination,
                            Protocol = NP(record.Protocol),
                            Severity = SeverityLevel.High,
                            Count = count,
                            WindowSeconds = window
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDhcpAbuse error: {ex}"); }
            return false;
        }

        // ===== R012 Suspicious TLS (flags surfaced in Info) =====
        private static bool DetectSuspiciousTls(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (record.DestinationPort != 443) return false;

                var info = record.Info ?? string.Empty;
                bool flagged = info.Contains("SelfSigned", StringComparison.OrdinalIgnoreCase)
                               || info.Contains("InvalidCert", StringComparison.OrdinalIgnoreCase)
                               || info.Contains("ExpiredCert", StringComparison.OrdinalIgnoreCase);
                if (!flagged) return false;

                if (SuppressRepeat(now, "R012", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                detection = new DetectionEvent
                {
                    RuleId = "R012",
                    Description = $"Suspicious TLS certificate observed ({ExtractTlsFlag(info)})",
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
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectSuspiciousTls error: {ex}"); }
            return false;
        }

        // ===== R013 Uncommon ports / Service–Port Anomaly (learner + IANA CSV) =====
        private static bool DetectUncommonPorts(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!record.DestinationPort.HasValue) return false;
                int port = record.DestinationPort.Value;

                // Fast path: only care about high ports; system ports flagged elsewhere
                if (port <= 1024) return false;
                if (_uncommonPortAllow.Contains(port)) return false;

                string proto = string.IsNullOrWhiteSpace(record.Protocol)
                    ? "TCP"
                    : record.Protocol.Trim().ToUpperInvariant();

                bool isTcp = proto == "TCP";
                bool isUdp = proto == "UDP";
                bool isEphemeral = port >= 49152; // IANA dynamic/private range 49152–65535 :contentReference[oaicite:4]{index=4}

                // *** NEW: UDP on ephemeral dest ports is almost always client-side noise.
                if (isUdp && isEphemeral)
                    return false;

                // Baseline gate: if our learner says this (port,proto) is common/legit *here*, don't alert
                if (AllowListLearner.IsAllowed(port, proto, now))
                    return false;

                // Prefer strong "new service" signal
                bool tcpSyn = isTcp && (record.Flags?.Contains("SYN") == true);

                // For UDP, require banner/service hint (to avoid noise)
                bool udpLikelyService =
                    !isTcp &&
                    (!string.IsNullOrWhiteSpace(record.ApplicationService) || record.Length > 0);

                if (!(tcpSyn || udpLikelyService))
                    return false;

                // Use the shared resolver so uncommon-port detection does not depend on a separate uninitialized map.
                string standardName =
                    PortServiceResolver.TryGetServiceInfo(port, proto, out var standardInfo) &&
                    !string.Equals(standardInfo.Source, "Heuristic", StringComparison.OrdinalIgnoreCase)
                        ? standardInfo.Name
                        : "unknown";
                string? observedService = record.ApplicationService;

                bool isUnknown = string.Equals(standardName, "unknown", StringComparison.OrdinalIgnoreCase);
                bool mismatch = !isUnknown &&
                                !string.IsNullOrWhiteSpace(observedService) &&
                                !string.Equals(standardName, observedService, StringComparison.OrdinalIgnoreCase);

                double anomaly = 0.0;
                var reasons = new List<string>(3);

                if (isUnknown)
                {
                    anomaly = Math.Max(anomaly, 0.85);
                    reasons.Add("Port not assigned/recognized in IANA registry");
                }
                if (mismatch)
                {
                    anomaly = Math.Max(anomaly, 0.75);
                    reasons.Add($"Observed service '{observedService}' ≠ standard '{standardName}'");
                }

                // Heuristics: non-ephemeral high ports acting like servers are more suspicious
                if (isEphemeral && !mismatch && isTcp && tcpSyn == false)
                    anomaly = Math.Max(anomaly, 0.60);

                if (!IsPrivateIp(record.Destination))
                    anomaly = Math.Min(1.0, anomaly + 0.05);

                double threshold = _cfg?.UncommonPortsAnomalyThreshold ?? UncommonPortsAnomalyThresholdDefault;
                if (anomaly < threshold) return false;

                if (SuppressRepeat(now, "R013", NS(record.Source), record.Destination, record.DestinationPort))
                    return false;

                var why = reasons.Count > 0 ? $" Why: {string.Join("; ", reasons)}." : string.Empty;
                string desc = isUnknown
                    ? $"Uncommon/unknown service on {port}/{proto}. Standard: unknown. Anomaly={anomaly:F2}.{why}"
                    : $"Service/port mismatch on {port}/{proto}. Standard: {standardName}, Observed: {observedService ?? "n/a"}. Anomaly={anomaly:F2}.{why}";

                detection = new DetectionEvent
                {
                    RuleId = "R013",
                    Description = desc,
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = port,
                    Protocol = NP(record.Protocol),
                    Severity = isUnknown
                        ? SeverityLevel.Low
                        : (anomaly >= 0.85 ? SeverityLevel.High : SeverityLevel.Medium),
                    Count = 1,
                    WindowSeconds = 0
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] DetectUncommonPorts error: {ex}");
                return false;
            }
        }

        // ===== R014 Cleartext creds =====
        private static readonly Regex _cleartextRegex = new(
            @"\b(USER\s+\S+|PASS\s+\S+|AUTH\s+LOGIN|MAIL\s+FROM:|RCPT\s+TO:)\b",
            RegexOptions.IgnoreCase | RegexOptions.Compiled);

        private static bool DetectCleartextCreds(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                var info = record.Info ?? string.Empty;
                if (!_cleartextRegex.IsMatch(info)) return false;

                if (SuppressRepeat(now, "R014", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                detection = new DetectionEvent
                {
                    RuleId = "R014",
                    Description = $"Possible cleartext credentials observed (heuristic match)",
                    SourceIp = NS(record.Source),
                    DestinationIp = record.Destination,
                    DestinationPort = record.DestinationPort,
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

        // ===== R015 ARP Spoofing =====
        private static bool DetectArpSpoofing(DateTime now, TrafficRecord record, out DetectionEvent detection)
        {
            detection = null!;
            try
            {
                if (!string.Equals(record.Protocol, "ARP", StringComparison.OrdinalIgnoreCase))
                    return false;

                BoundDictionary(_arpTable, 50000);

                var info = record.Info ?? string.Empty;

                var m = _arpIsAtRegex.Match(info);
                if (!m.Success) return false;

                string ip = m.Groups["ip"].Value;
                string mac = m.Groups["mac"].Value.ToUpperInvariant();

                if (string.IsNullOrWhiteSpace(ip) || string.IsNullOrWhiteSpace(mac))
                    return false;

                if (!IsPrivateIp(ip)) return false;

                if (_arpTable.TryGetValue(ip, out var prevMac))
                {
                    if (!string.Equals(prevMac, mac, StringComparison.OrdinalIgnoreCase))
                    {
                        if (SuppressRepeat(now, "R015", ip, null, null)) return false;

                        detection = new DetectionEvent
                        {
                            RuleId = "R015",
                            Description = $"ARP spoofing suspected: {ip} previously at {prevMac}, now claims {mac}",
                            SourceIp = ip,
                            Protocol = "ARP",
                            Severity = SeverityLevel.High,
                            Count = 1,
                            WindowSeconds = 0
                        };

                        _arpTable[ip] = mac;
                        return true;
                    }
                }
                else
                {
                    _arpTable[ip] = mac;
                }
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
                if (!record.ReputationScore.HasValue) return false;
                int cutoff = s.AbuseIpdbThreshold();

                if (record.ReputationScore.Value >= cutoff)
                {
                    if (SuppressRepeat(now, "R016", NS(record.Source), record.Destination, record.DestinationPort)) return false;

                    detection = new DetectionEvent
                    {
                        RuleId = "R016",
                        Description = $"AbuseIPDB score {record.ReputationScore} ≥ {cutoff}",
                        SourceIp = NS(record.Source),
                        DestinationIp = record.Destination,
                        DestinationPort = record.DestinationPort,
                        Protocol = NP(record.Protocol),
                        Severity = record.ReputationScore.Value >= 90 ? SeverityLevel.Critical : SeverityLevel.High,
                        Count = record.ReputationScore.Value,
                        WindowSeconds = 0
                    };

                    // Penalize service to resist poisoning
                    if (record.DestinationPort is int p && !string.IsNullOrWhiteSpace(record.Protocol))
                        AllowListLearner.MarkBad(p, record.Protocol, now, "reputation");

                    return true;
                }
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
                BoundDictionary(_hostSweeps, 10000);

                if (record.Source is not { Length: > 0 } src || record.DestinationPort is not int dport) return false;
                if (string.IsNullOrWhiteSpace(record.Destination) || !IsPrivateIp(record.Destination)) return false;

                var window = _cfg.HostSweepWindowSeconds ?? HostSweepWindowSeconds;
                var threshold = ScaleCount(_cfg.HostSweepDistinctHostsThreshold ?? HostSweepDistinctHostsThreshold, s);

                var map = _hostSweeps.GetOrAdd((src, dport), _ => new ConcurrentDictionary<string, DateTime>());
                map[record.Destination] = now;

                var cutoff = now.AddSeconds(-window);
                foreach (var k in map.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    map.TryRemove(k, out _);

                int uniq = map.Count;
                if (uniq >= threshold)
                {
                    if (SuppressRepeat(now, "R017", src, null, dport)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R017",
                        Description = $"Likely internal host sweep from {src} on port {dport} ({uniq} hosts/{window}s)",
                        SourceIp = src,
                        DestinationPort = dport,
                        Protocol = NP(record.Protocol),
                        Severity = SeverityLevel.High,
                        Count = uniq,
                        WindowSeconds = window
                    };
                    map.Clear();
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
                var info = r.Info ?? string.Empty;
                bool looksHttp = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                                 || (r.HttpMethod is not null)
                                 || info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase)
                                 || info.StartsWith("GET ", StringComparison.OrdinalIgnoreCase)
                                 || info.StartsWith("POST ", StringComparison.OrdinalIgnoreCase)
                                 || info.StartsWith("HEAD ", StringComparison.OrdinalIgnoreCase)
                                 || info.StartsWith("PUT ", StringComparison.OrdinalIgnoreCase)
                                 || info.StartsWith("DELETE ", StringComparison.OrdinalIgnoreCase);

                if (!looksHttp) return false;
                if (string.IsNullOrWhiteSpace(r.Destination) || !IPAddress.TryParse(r.Destination, out _)) return false;
                if (_httpHostHeaderRx.IsMatch(info)) return false;

                if (SuppressRepeat(now, "R018", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R018",
                    Description = "HTTP request to IP literal without Host header",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
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
                var info = r.Info ?? string.Empty;
                bool looksHttp = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                                 || (r.HttpMethod is not null)
                                 || info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase);
                if (!looksHttp) return false;

                var firstLine = info.Split('\n').FirstOrDefault() ?? string.Empty;
                var parts = firstLine.Split(' ');
                var uri = parts.Length >= 2 ? parts[1] : string.Empty;
                if (uri.Length == 0) return false;

                int lenThresh = ScaleCount(_cfg.HttpUriLenThreshold ?? HttpUriLenThreshold, s);
                int chunkThresh = ScaleCount(_cfg.HttpUriChunkLenThreshold ?? HttpUriChunkLenThreshold, s);
                double entThresh = ScaleFloat(_cfg.HttpUriEntropyThreshold ?? HttpUriEntropyThreshold, s);

                bool tooLong = uri.Length >= lenThresh;
                bool hasChunk = false;
                foreach (Match m in _b64Like.Matches(uri))
                {
                    if (m.Length >= chunkThresh && ShannonEntropy(m.Value) >= entThresh) { hasChunk = true; break; }
                }
                if (!(tooLong || hasChunk)) return false;

                if (SuppressRepeat(now, "R019", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R019",
                    Description = $"Suspicious HTTP URI (len={uri.Length}{(hasChunk ? ", high-entropy chunk" : "")})",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
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
                if (r.DestinationPort != 25 || IsPrivateIp(r.Destination)) return false;

                var allow = _cfg.SmtpAllowedSources ?? new List<string>();
                if (!string.IsNullOrEmpty(r.Source) && allow.Exists(x => string.Equals(x, r.Source, StringComparison.OrdinalIgnoreCase)))
                    return false;

                if (SuppressRepeat(now, "R020", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R020",
                    Description = "Direct outbound SMTP (port 25) to Internet from non-allowed source",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = 25,
                    Protocol = NP(r.Protocol),
                    Severity = SeverityLevel.High,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectSmtpEgress25 error: {ex}"); }
            return false;
        }

        // ===== R021 ICMP tunneling suspicion (windowed bytes + avg payload) =====
        private static bool DetectIcmpTunnel(DateTime now, TrafficRecord r, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)) return false;

                BoundDictionary(_icmpWindow, 20000);
                BoundDictionary(_icmpBytes, 20000);
                BoundDictionary(_icmpTimes, 20000);

                int window = _cfg.IcmpWindowSeconds ?? IcmpWindowSeconds;
                int cntThresh = ScaleCount(_cfg.IcmpPktCountThreshold ?? IcmpPktCountThreshold, s);
                long byteThresh = ScaleBytes(_cfg.IcmpTotalBytesThreshold ?? IcmpTotalBytesThreshold, s);

                var key = NS(r.Source);
                var samples = _icmpWindow.GetOrAdd(key, _ => new List<(DateTime ts, int bytes)>(64));
                int count, total;
                lock (samples)
                {
                    samples.Add((now, Math.Max(0, r.Length)));
                    var cutoff = now.AddSeconds(-window);
                    int write = 0; total = 0;
                    for (int i = 0; i < samples.Count; i++)
                    {
                        if (samples[i].ts >= cutoff)
                        {
                            samples[write++] = samples[i];
                            total += samples[i].bytes;
                        }
                    }
                    if (write != samples.Count) samples.RemoveRange(write, samples.Count - write);
                    count = write;
                }

                double avgPayload = count > 0 ? (double)total / count : 0.0;

                if ((count >= cntThresh || total >= byteThresh) && avgPayload >= 24.0)
                {
                    if (SuppressRepeat(now, "R021", key, r.Destination, null)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R021",
                        Description = $"Suspicious ICMP activity (pkts={count}, bytes={total}/{window}s, avg={avgPayload:F0}B)",
                        SourceIp = key,
                        DestinationIp = r.Destination,
                        Protocol = "ICMP",
                        Severity = SeverityLevel.Medium,
                        Count = count,
                        WindowSeconds = window
                    };
                    lock (samples) samples.Clear();
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectIcmpTunnel error: {ex}"); }
            return false;
        }

        // ===== R022 DNS NXDOMAIN spike =====
        private static bool DetectDnsNxSpike(DateTime now, TrafficRecord r, Sensitivity s, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool isDns = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
                             || (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) && r.DestinationPort == 53);
                if (!isDns || r.Source is not { Length: > 0 }) return false;

                BoundDictionary(_nxdomain, 20000);

                var info = r.Info ?? string.Empty;
                bool nxd = info.IndexOf("NXDOMAIN", StringComparison.OrdinalIgnoreCase) >= 0
                           || info.IndexOf("RCODE=NXDOMAIN", StringComparison.OrdinalIgnoreCase) >= 0;
                if (!nxd) return false;

                var window = _cfg.DnsNxWindowSeconds ?? DnsNxWindowSeconds;
                var threshold = ScaleCount(_cfg.DnsNxThreshold ?? DnsNxThreshold, s);

                var list = _nxdomain.GetOrAdd(r.Source, _ => new List<DateTime>(threshold * 2));
                lock (list)
                {
                    list.Add(now);
                    int count = TrimAndCount(list, now, window);
                    if (count >= threshold)
                    {
                        if (SuppressRepeat(now, "R022", r.Source, r.Destination, r.DestinationPort)) return false;
                        det = new DetectionEvent
                        {
                            RuleId = "R022",
                            Description = $"NXDOMAIN spike from {r.Source} ({count}/{window}s)",
                            SourceIp = r.Source,
                            DestinationIp = r.Destination,
                            Protocol = NP(r.Protocol),
                            Severity = SeverityLevel.High,
                            Count = count,
                            WindowSeconds = window
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] DetectDnsNxSpike error: {ex}"); }
            return false;
        }

        // ===== R023 TLS to public IP without SNI (exclude QUIC; require persistence) =====
        private static bool DetectTlsNoSniToIp(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                // TLS-like (classic TLS on 443 or explicit TLS proto)
                bool tlsLike = (r.DestinationPort == 443)
                               || string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase);
                if (!tlsLike) return false;

                // Exclude QUIC/HTTP3 cases entirely
                if (r.IsQuic || r.QuicVersion is not null || r.QuicAlpn is not null)
                    return false;

                // Missing SNI or SNI is an IP literal
                bool sniMissingOrIp = string.IsNullOrWhiteSpace(r.Sni) || IPAddress.TryParse(r.Sni!, out _);
                if (!sniMissingOrIp) return false;

                // Must be going to a public IP literal
                if (string.IsNullOrWhiteSpace(r.Destination)) return false;
                if (!IPAddress.TryParse(r.Destination, out var _)) return false;
                if (IsPrivateIp(r.Destination)) return false;

                // Require ≥3 hits to the same destination within 5 minutes (persistence)
                string key = $"R023:{NS(r.Source)}->{r.Destination}";
                var list = _packetTimes.GetOrAdd(key, _ => new List<DateTime>(8));
                lock (list)
                {
                    list.Add(now);
                    if (TrimAndCount(list, now, 300) < 3) // 5 minutes
                        return false;
                }

                if (SuppressRepeat(now, "R023", NS(r.Source), r.Destination, r.DestinationPort)) return false;

                det = new DetectionEvent
                {
                    RuleId = "R023",
                    Description = "TLS to public IP without SNI (repeated to same host)",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = SeverityLevel.Medium,
                    Count = 1,
                    WindowSeconds = 300
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R023 error: {ex}");
                return false;
            }
        }

        // ===== R024 Rare/novel TLS client fingerprint (JA3/JA4) =====
        private static bool DetectRareTlsFingerprint(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string? key = r.Ja4 ?? r.Ja3;
                if (string.IsNullOrWhiteSpace(key)) return false;

                BoundedMerge(_ja4Counts, key!, now);
                var stat = _ja4Counts[key!];

                // Trigger on first sighting(s)
                if (stat.Count <= 3)
                {
                    if (SuppressRepeat(now, "R024", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R024",
                        Description = $"Rare TLS fingerprint observed ({(r.Ja4 ?? r.Ja3)}) count={stat.Count}",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = NP(r.Protocol),
                        Severity = stat.Count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                        Count = stat.Count
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R024 error: {ex}"); }
            return false;
        }

        // ===== R025 TLS certificate expired or expiring soon =====
        private static bool DetectTlsCertExpiry(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort != 443) return false;
                if (!r.CertValidTo.HasValue) return false;

                var daysLeft = (r.CertValidTo.Value - now).TotalDays;
                if (daysLeft < 0)
                {
                    if (SuppressRepeat(now, "R025", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R025",
                        Description = "TLS certificate expired",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.High,
                        Count = (int)Math.Abs(Math.Round(daysLeft))
                    };
                    return true;
                }
                if (daysLeft <= 7)
                {
                    if (SuppressRepeat(now, "R025", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R025",
                        Description = $"TLS certificate expiring soon (≤7 days, left≈{daysLeft:F1})",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = (int)Math.Ceiling(daysLeft)
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R025 error: {ex}"); }
            return false;
        }

        // ===== R026 SMB/RPC to Internet =====
        private static bool DetectSmbToInternet(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                int? p = r.DestinationPort;
                if (p is not (139 or 445)) return false;
                if (IsPrivateIp(r.Destination)) return false;

                if (SuppressRepeat(now, "R026", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R026",
                    Description = "SMB/RPC traffic to Internet (likely misconfiguration or data leakage risk)",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = p,
                    Protocol = NP(r.Protocol),
                    Severity = SeverityLevel.High,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R026 error: {ex}"); }
            return false;
        }

        // ===== R027 Admin service egress to Internet (RDP/SSH/WinRM/Telnet/FTP) =====
        private static bool DetectAdminEgress(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (r.DestinationPort is null) return false;
                int p = r.DestinationPort.Value;
                if (!AuthPorts.Contains(p)) return false;
                if (IsPrivateIp(r.Destination)) return false;

                if (SuppressRepeat(now, "R027", NS(r.Source), r.Destination, p)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R027",
                    Description = $"Administrative service egress to Internet on port {p}",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = p,
                    Protocol = NP(r.Protocol),
                    Severity = SeverityLevel.Medium,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R027 error: {ex}"); }
            return false;
        }

        // ===== R028 Direct external DNS (bypassing resolver) =====
        private static bool DetectExternalDnsDirect(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!(string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) || string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)))
                    return false;
                if (r.DestinationPort != 53) return false;

                if (IsPrivateIp(NS(r.Source)) && !IsPrivateIp(r.Destination))
                {
                    if (SuppressRepeat(now, "R028", NS(r.Source), r.Destination, 53)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R028",
                        Description = "Direct DNS to Internet (resolver bypass)",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = 53,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = 1
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R028 error: {ex}"); }
            return false;
        }

        // ===== R029 QUIC anomaly (require non-443 AND missing ALPN; light rate-limit) =====
        private static bool DetectQuicAnomaly(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                // Only proceed if it looks QUIC-ish at all
                bool quicish =
                    r.IsQuic ||
                    r.QuicVersion is not null ||
                    r.QuicAlpn is not null ||
                    string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase);
                if (!quicish) return false;

                if (r.DestinationPort is not int dp)
                    return false;

                // *** NEW: obvious non-QUIC well-known ports (DNS/NTP) are noise for this rule.
                if (dp == 53 || dp == 123)
                    return false;

                bool nonStandardPort = dp != 443;
                bool missingAlpn = string.IsNullOrWhiteSpace(r.QuicAlpn);

                // Require BOTH for precision
                if (!(nonStandardPort && missingAlpn))
                    return false;

                // Light per-source debounce (max 3/minute)
                var rlKey = $"R029:{NS(r.Source)}";
                var times = _packetTimes.GetOrAdd(rlKey, _ => new List<DateTime>(16));
                lock (times)
                {
                    times.Add(now);
                    if (TrimAndCount(times, now, 60) > 3)
                        return false;
                }

                if (SuppressRepeat(now, "R029", NS(r.Source), r.Destination, r.DestinationPort)) return false;

                det = new DetectionEvent
                {
                    RuleId = "R029",
                    Description = "QUIC anomaly: non-443 port AND missing ALPN",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = dp,
                    Protocol = "QUIC",
                    Severity = SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R029 error: {ex}"); }
            return false;
        }

        // ===== R030 Internal admin lateral sweep =====
        private static bool DetectAdminLateralSweep(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                BoundDictionary(_adminSweeps, 10000);

                if (r.Source is not { Length: > 0 } src || r.DestinationPort is not int p) return false;
                if (!AuthPorts.Contains(p)) return false;
                if (string.IsNullOrWhiteSpace(r.Destination) || !IsPrivateIp(r.Destination)) return false;

                const int window = 60;
                const int threshold = 8;

                var map = _adminSweeps.GetOrAdd((src, p), _ => new ConcurrentDictionary<string, DateTime>());
                map[r.Destination] = now;

                var cutoff = now.AddSeconds(-window);
                foreach (var k in map.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    map.TryRemove(k, out _);

                int uniq = map.Count;
                if (uniq >= threshold)
                {
                    if (SuppressRepeat(now, "R030", src, null, p)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R030",
                        Description = $"Admin lateral sweep from {src} on {p} ({uniq} hosts/{window}s)",
                        SourceIp = src,
                        DestinationPort = p,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.High,
                        Count = uniq,
                        WindowSeconds = window
                    };
                    map.Clear();
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R030 error: {ex}"); }
            return false;
        }

        // ===== R031 DNS TXT spike (exfil heuristic) =====
        private static bool DetectDnsTxtSpike(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool isDns = string.Equals(r.Protocol, "DNS", StringComparison.OrdinalIgnoreCase) || (string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase) && r.DestinationPort == 53);
                if (!isDns) return false;

                if (!string.Equals(r.DnsQtype, "TXT", StringComparison.OrdinalIgnoreCase)) return false;

                BoundDictionary(_dnsTxtBySrc, 20000);

                const int window = 60;
                const int threshold = 15;

                var list = _dnsTxtBySrc.GetOrAdd(NS(r.Source), _ => new List<DateTime>(threshold * 2));
                lock (list)
                {
                    list.Add(now);
                    int count = TrimAndCount(list, now, window);
                    if (count >= threshold)
                    {
                        if (SuppressRepeat(now, "R031", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                        det = new DetectionEvent
                        {
                            RuleId = "R031",
                            Description = $"DNS TXT query spike from {NS(r.Source)} ({count}/{window}s)",
                            SourceIp = NS(r.Source),
                            DestinationIp = r.Destination,
                            Protocol = NP(r.Protocol),
                            Severity = SeverityLevel.High,
                            Count = count,
                            WindowSeconds = window
                        };
                        list.Clear();
                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R031 error: {ex}"); }
            return false;
        }

        // ===== R032 Suspicious/empty HTTP User-Agent =====
        private static readonly Regex _susUa = new(@"(?i)\b(curl|wget|python-requests|Go-http-client|powershell|libwww-perl|java/\d|okhttp)\b", RegexOptions.Compiled);
        private static bool DetectSuspiciousUserAgent(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool httpLike = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) || (r.HttpMethod is not null) || (r.HttpUserAgent is not null);
                if (!httpLike) return false;

                string ua = r.HttpUserAgent ?? string.Empty;
                bool emptyUa = string.IsNullOrWhiteSpace(ua);
                bool badUa = _susUa.IsMatch(ua);

                if (!(emptyUa || badUa)) return false;

                if (SuppressRepeat(now, "R032", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R032",
                    Description = emptyUa ? "HTTP request with empty User-Agent" : $"HTTP request with suspicious User-Agent: {ua}",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTP",
                    Severity = badUa ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R032 error: {ex}"); }
            return false;
        }

        // ===== R033 ICMP oversized echo payload =====
        private static bool DetectIcmpOversized(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!string.Equals(r.Protocol, "ICMP", StringComparison.OrdinalIgnoreCase)) return false;
                if (r.Length <= 0) return false;

                const int sizeThresh = 1000; // bytes (payload + headers as observed length)
                if (r.Length >= sizeThresh)
                {
                    if (SuppressRepeat(now, "R033", NS(r.Source), r.Destination, null)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R033",
                        Description = $"ICMP oversized packet length={r.Length} bytes",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        Protocol = "ICMP",
                        Severity = SeverityLevel.Medium,
                        Count = r.Length
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R033 error: {ex}"); }
            return false;
        }

        // ===== R034 DNS-over-HTTPS (DoH) heuristic =====
        private static bool DetectDoHHeuristic(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool looksDoH = IsDoHLike(r);
                if (!looksDoH) return false;

                if (SuppressRepeat(now, "R034", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R034",
                    Description = "Possible DNS-over-HTTPS (DoH) detected",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTP",
                    Severity = SeverityLevel.Medium,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R034 error: {ex}"); }
            return false;
        }

        // ===== R035 Rare SSH client fingerprint (HASSH/JA4SSH) =====
        private static bool DetectRareSshFingerprint(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string? key = r.Ja4SSH ?? r.Hassh;
                if (string.IsNullOrWhiteSpace(key)) return false;

                BoundedMerge(_sshFpCounts, key!, now);
                var stat = _sshFpCounts[key!];

                if (stat.Count <= 3)
                {
                    if (SuppressRepeat(now, "R035", NS(r.Source), r.Destination, r.DestinationPort)) return false;
                    det = new DetectionEvent
                    {
                        RuleId = "R035",
                        Description = $"Rare SSH fingerprint observed ({key}) count={stat.Count}",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = "SSH",
                        Severity = stat.Count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                        Count = stat.Count
                    };
                    return true;
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R035 error: {ex}"); }
            return false;
        }

        // ===== R036 Heavy egress to single external host (per-pair exfil) =====
        private static bool DetectPairExfiltration(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                BoundDictionary(_pairBytes, 20000);

                if (r.Length <= 0) return false;
                if (string.IsNullOrWhiteSpace(r.Destination) || IsPrivateIp(r.Destination)) return false;
                if (string.IsNullOrWhiteSpace(r.Source)) return false;

                const int window = 120;               // seconds
                const int thresholdBytes = 20_000_000; // 20 MB per 2 min to a single host

                var key = (NS(r.Source), r.Destination);
                var list = _pairBytes.GetOrAdd(key, _ => new List<(DateTime, int)>(capacity: 64));
                lock (list)
                {
                    list.Add((now, r.Length));
                    var cutoff = now.AddSeconds(-window);
                    list.RemoveAll(t => t.ts < cutoff);

                    int total = 0;
                    for (int i = 0; i < list.Count; i++) total += list[i].bytes;

                    if (total >= thresholdBytes)
                    {
                        if (SuppressRepeat(now, "R036", key.Item1, key.Item2, r.DestinationPort)) return false;
                        det = new DetectionEvent
                        {
                            RuleId = "R036",
                            Description = $"High-volume egress from {key.Item1} to {key.Item2}: {total} bytes / {window}s",
                            SourceIp = key.Item1,
                            DestinationIp = key.Item2,
                            DestinationPort = r.DestinationPort,
                            Protocol = NP(r.Protocol),
                            Severity = SeverityLevel.Critical,
                            Count = total,
                            WindowSeconds = window
                        };
                        list.Clear();

                        // Penalize service (if any) due to heavy suspicious egress to a single host.
                        if (r.DestinationPort is int p3 && !string.IsNullOrWhiteSpace(r.Protocol))
                            AllowListLearner.MarkBad(p3, r.Protocol, now, "heavy-egress");

                        return true;
                    }
                }
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R036 error: {ex}"); }
            return false;
        }

        // ===== R037 JA4 drift per SNI (rare SNI -> multiple JA4s) =====
        private static bool DetectJa4DriftPerSni(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                // Need a concrete SNI and JA4 client fingerprint
                string? sni = r.Sni ?? r.TlsSni;
                if (string.IsNullOrWhiteSpace(sni)) return false;
                string? ja4 = r.Ja4;
                if (string.IsNullOrWhiteSpace(ja4)) return false;

                // Focus on TLS/HTTPS/QUIC-ish flows only
                bool tlsLike =
                    r.DestinationPort == 443
                    || string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                    || string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase)
                    || r.IsQuic;
                if (!tlsLike) return false;

                const int windowSeconds = 3600;      // 1h drift window
                const int maxJa4PerSni = 16;         // bound per-SNI distinct JA4s
                const int minDistinct = 3;           // require at least 3 distinct JA4s
                const int minTotal = 5;              // minimum connections in-window
                const int maxTotalForRare = 50;      // rare SNI guard: don't trigger on very popular SNI

                var inner = _sniJa4Drift.GetOrAdd(sni, _ => new ConcurrentDictionary<string, (int Count, DateTime LastSeen)>());

                // Update per-SNI JA4 stats
                inner.AddOrUpdate(
                    ja4,
                    _ => (1, now),
                    (_, prev) => (prev.Count + 1, now));

                // Time-based cleanup
                var cutoff = now.AddSeconds(-windowSeconds);
                foreach (var kv in inner.Where(kv => kv.Value.LastSeen < cutoff).ToList())
                    inner.TryRemove(kv.Key, out _);

                // Bound per-SNI distinct JA4s
                if (inner.Count > maxJa4PerSni)
                {
                    foreach (var kv in inner.OrderBy(kv => kv.Value.LastSeen)
                                             .Take(inner.Count - maxJa4PerSni)
                                             .ToList())
                    {
                        inner.TryRemove(kv.Key, out _);
                    }
                }

                // Bound global SNI map
                BoundDictionary(_sniJa4Drift, 5000);

                int distinct = inner.Count;
                int total = inner.Sum(x => x.Value.Count);

                if (distinct < minDistinct || total < minTotal || total > maxTotalForRare)
                    return false;

                if (SuppressRepeat(now, "R037", NS(r.Source), r.Destination, r.DestinationPort)) return false;

                var severity = distinct >= 5 ? SeverityLevel.High : SeverityLevel.Medium;

                det = new DetectionEvent
                {
                    RuleId = "R037",
                    Description = $"JA4 drift for rare SNI '{sni}' (distinctJA4={distinct}, conns={total}/{windowSeconds}s)",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = severity,
                    Count = distinct,
                    WindowSeconds = windowSeconds
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R037 error: {ex}");
                return false;
            }
        }

        // ===== R038 Encrypted DNS bootstrap (QUIC high-entropy SNI + DoH surge) =====
        private static bool DetectEncryptedDnsBootstrap(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string src = NS(r.Source);
                if (string.IsNullOrWhiteSpace(src)) return false;

                const int windowSeconds = 300; // 5 min
                const int dohThreshold = 10;   // DoH requests in window
                const int quicThreshold = 3;   // high-entropy QUIC SNIs in window
                const double sniEntropyThreshold = 3.5;

                bool isDoH = IsDoHLike(r);
                bool isQuicHiEntropy = false;

                // QUIC / HTTP3 handshake with SNI that looks random-ish
                if ((r.IsQuic
                     || string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase)
                     || r.QuicAlpn is { Length: > 0 })
                    && !string.IsNullOrWhiteSpace(r.Sni))
                {
                    double ent = ShannonEntropy(r.Sni!);
                    isQuicHiEntropy = ent >= sniEntropyThreshold;
                }

                if (!isDoH && !isQuicHiEntropy)
                    return false;

                if (isDoH)
                {
                    var list = _dohBySrc.GetOrAdd(src, _ => new List<DateTime>(dohThreshold * 2));
                    lock (list)
                    {
                        list.Add(now);
                        TrimAndCount(list, now, windowSeconds);
                    }
                    BoundDictionary(_dohBySrc, 10000);
                }

                if (isQuicHiEntropy)
                {
                    var list = _quicHiEntropyBySrc.GetOrAdd(src, _ => new List<DateTime>(quicThreshold * 2));
                    lock (list)
                    {
                        list.Add(now);
                        TrimAndCount(list, now, windowSeconds);
                    }
                    BoundDictionary(_quicHiEntropyBySrc, 10000);
                }

                int dohCount = 0;
                if (_dohBySrc.TryGetValue(src, out var dohList) && dohList != null)
                {
                    lock (dohList)
                    {
                        dohCount = TrimAndCount(dohList, now, windowSeconds);
                    }
                }

                int quicCount = 0;
                if (_quicHiEntropyBySrc.TryGetValue(src, out var quicList) && quicList != null)
                {
                    lock (quicList)
                    {
                        quicCount = TrimAndCount(quicList, now, windowSeconds);
                    }
                }

                if (dohCount < dohThreshold || quicCount < quicThreshold)
                    return false;

                if (SuppressRepeat(now, "R038", src, r.Destination, r.DestinationPort)) return false;

                int score = dohCount * 2 + quicCount; // simple "probability-ish" score
                var severity = score >= 30 ? SeverityLevel.High : SeverityLevel.Medium;

                det = new DetectionEvent
                {
                    RuleId = "R038",
                    Description = $"Encrypted DNS bootstrap suspected from {src} (DoH={dohCount}, QUIC-hi-entropy={quicCount}/{windowSeconds}s, score={score})",
                    SourceIp = src,
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = severity,
                    Count = score,
                    WindowSeconds = windowSeconds
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R038 error: {ex}");
                return false;
            }
        }

        // Shared helper for DoH-ish HTTP detection (R034 & R038)
        private static bool IsDoHLike(TrafficRecord r)
        {
            var info = r.Info ?? string.Empty;
            bool httpLike = string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                            || (r.HttpMethod is not null)
                            || info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase);

            if (!httpLike) return false;

            var firstLine = info.Split('\n').FirstOrDefault() ?? string.Empty;
            var parts = firstLine.Split(' ');
            string? method = parts.Length > 0 ? parts[0] : null;
            string? uri = r.HttpUri ?? (parts.Length > 1 ? parts[1] : null);

            var headers = r.HttpRequestHeaders ?? info;

            bool looksDoH =
                (uri?.Contains("/dns-query", StringComparison.OrdinalIgnoreCase) == true)
                || headers.Contains("application/dns-message", StringComparison.OrdinalIgnoreCase);

            // Slight guard: only GET/POST to keep noise low
            if (!looksDoH) return false;
            if (!string.Equals(method, "GET", StringComparison.OrdinalIgnoreCase) &&
                !string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                return false;

            return true;
        }

        // ===== R039 ASN novelty on sensitive VLANs =====
        private static bool DetectAsnNoveltySensitive(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (string.IsNullOrWhiteSpace(r.WhoisASN)) return false;
                if (!IsSensitiveVlanFlow(r)) return false;

                // Normalize ASN string (e.g. "AS1234 Example Ltd" -> "AS1234")
                string asnRaw = r.WhoisASN!.Trim();
                int spaceIdx = asnRaw.IndexOf(' ');
                string asn = spaceIdx > 0 ? asnRaw.Substring(0, spaceIdx) : asnRaw;

                // Track where we've seen this ASN at all
                var stats = _asnSeenAnywhere.AddOrUpdate(
                    asn,
                    _ => (FirstSeen: now, LastSeen: now),
                    (_, prev) => (prev.FirstSeen, LastSeen: now));

                // Age out very old ASNs so state doesn't grow forever
                var cutoff = now.AddDays(-7);
                foreach (var kv in _asnSeenAnywhere.Where(kv => kv.Value.LastSeen < cutoff).ToList())
                    _asnSeenAnywhere.TryRemove(kv.Key, out _);
                BoundDictionary(_asnSeenAnywhere, 20000);
                BoundDictionary(_asnSeenOnSensitive, 5000);

                // First time this ASN has ever talked to a sensitive segment in this Carthago lifetime?
                bool firstOnSensitive = _asnSeenOnSensitive.TryAdd(asn, now);
                if (!firstOnSensitive) return false;

                // If we've never seen this ASN anywhere before, it's more suspicious.
                bool seenElsewhereBefore = stats.FirstSeen < now.AddMinutes(-10);

                if (SuppressRepeat(now, "R039", NS(r.Source), r.Destination, r.DestinationPort)) return false;

                var severity = seenElsewhereBefore ? SeverityLevel.Medium : SeverityLevel.High;

                det = new DetectionEvent
                {
                    RuleId = "R039",
                    Description = $"New ASN {asn} observed talking to sensitive segment (networkType={r.NetworkType ?? "n/a"})",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = severity,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R039 error: {ex}");
                return false;
            }
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

        // R041: JA4 fan-out sweep — per (src, ja4) -> distinct SNI
        private static readonly ConcurrentDictionary<(string Src, string Ja4), ConcurrentDictionary<string, DateTime>> _ja4SniFanout =
            new();

        // R042: Uncommon QUIC ALPN rarity tracking
        private static readonly ConcurrentDictionary<string, (int Count, DateTime First, DateTime Last)> _quicAlpnCounts =
            new(StringComparer.OrdinalIgnoreCase);

        // R043: SNI seen on TLS, then Host seen on HTTP to same dst
        private static readonly ConcurrentDictionary<(string Src, string Dst), (string Sni, DateTime Ts)> _tlsSniByFlow =
            new();

        // R048: Alternate DoH pattern rate-limiting
        private static readonly ConcurrentDictionary<string, List<DateTime>> _altDohSeenBySrc =
            new(StringComparer.Ordinal);

        // ===== R040: Long-lived, low-throughput encrypted session =====
        private static bool DetectEncryptedLowAndSlow(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool encryptedLike =
                    r.DestinationPort == 443 ||
                    string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase) ||
                    r.IsQuic;

                if (!encryptedLike) return false;
                if (string.IsNullOrWhiteSpace(r.Source) || string.IsNullOrWhiteSpace(r.Destination)) return false;
                if (IsPrivateIp(r.Destination)) return false; // focus on Internet C2

                var key = (Src: NS(r.Source), Dst: r.Destination, Port: r.DestinationPort);
                var fs = _encFlow.GetOrAdd(key, _ => new FlowStat
                {
                    First = now,
                    Last = now,
                    Bytes = 0,
                    Count = 0
                });

                lock (fs)
                {
                    fs.Last = now;
                    fs.Bytes += Math.Max(0, r.Length);
                    fs.Count++;

                    var lifetime = (fs.Last - fs.First).TotalSeconds;
                    if (lifetime < 900) return false;   // < 15 minutes
                    if (fs.Count < 12) return false;    // < 12 packets/records
                    if (fs.Bytes > 300_000) return false; // > 300KB looks like normal browsing/transfer

                    if (SuppressRepeat(now, "R040", key.Src, key.Dst, key.Port))
                        return false;

                    det = new DetectionEvent
                    {
                        RuleId = "R040",
                        Description = $"Long-lived low-throughput encrypted session {key.Src} → {key.Dst} (dur≈{lifetime / 60:F1}m, msgs={fs.Count}, bytes={fs.Bytes})",
                        SourceIp = key.Src,
                        DestinationIp = key.Dst,
                        DestinationPort = key.Port,
                        Protocol = NP(r.Protocol),
                        Severity = SeverityLevel.Medium,
                        Count = fs.Count,
                        WindowSeconds = (int)Math.Round(lifetime)
                    };

                    _encFlow.TryRemove(key, out _); // one-shot per flow window
                    return true;
                }
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R040 error: {ex}");
                return false;
            }
        }

        // ===== R041: JA4 fan-out sweep (same JA4 -> many SNIs quickly) =====
        private static bool DetectJa4FanoutSweep(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                string? ja4 = r.Ja4;
                string? sni = r.Sni;
                if (string.IsNullOrWhiteSpace(ja4) || string.IsNullOrWhiteSpace(sni)) return false;
                if (IsPrivateIp(r.Destination)) return false; // focus on Internet pivot

                const int windowSeconds = 60;
                const int distinctThreshold = 8;

                var key = (Src: NS(r.Source), Ja4: ja4);
                var map = _ja4SniFanout.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
                map[sni] = now;

                var cutoff = now.AddSeconds(-windowSeconds);
                foreach (var k in map.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToList())
                    map.TryRemove(k, out _);

                int distinct = map.Count;
                BoundDictionary(_ja4SniFanout, 20_000);

                if (distinct < distinctThreshold)
                    return false;

                if (SuppressRepeat(now, "R041", key.Src, r.Destination, r.DestinationPort))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R041",
                    Description = $"JA4 fan-out sweep from {key.Src} — JA4={ja4}, distinct SNI={distinct}/{windowSeconds}s",
                    SourceIp = key.Src,
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol),
                    Severity = SeverityLevel.High,
                    Count = distinct,
                    WindowSeconds = windowSeconds
                };

                map.Clear();
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R041 error: {ex}");
                return false;
            }
        }

        // ===== R042: Uncommon QUIC ALPN =====
        private static bool DetectUncommonQuicAlpn(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                bool quicish =
                    r.IsQuic ||
                    string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase) ||
                    r.QuicAlpn is { Length: > 0 };

                if (!quicish) return false;

                string? alpn = r.QuicAlpn;
                if (string.IsNullOrWhiteSpace(alpn)) return false;

                var a = alpn.Trim().ToLowerInvariant();
                bool common =
                    a.StartsWith("h3", StringComparison.Ordinal) ||
                    a.StartsWith("hq-", StringComparison.Ordinal) ||
                    a == "http/3" ||
                    a == "h3-29" ||
                    a == "h3-32";

                if (common) return false;

                var entry = _quicAlpnCounts.AddOrUpdate(
                    a,
                    _ => (Count: 1, First: now, Last: now),
                    (_, prev) => (Count: prev.Count + 1, First: prev.First, Last: now));

                // Evict stale entries if map grows too large
                if (_quicAlpnCounts.Count > 5000)
                {
                    var cutoff = now.AddHours(-6);
                    foreach (var kv in _quicAlpnCounts.Where(kv => kv.Value.Last < cutoff).Take(500).ToList())
                        _quicAlpnCounts.TryRemove(kv.Key, out _);
                }

                if (entry.Count <= 3 && !IsPrivateIp(r.Destination))
                {
                    if (SuppressRepeat(now, "R042", NS(r.Source), r.Destination, r.DestinationPort))
                        return false;

                    det = new DetectionEvent
                    {
                        RuleId = "R042",
                        Description = $"Uncommon QUIC ALPN negotiated: '{alpn}' (count={entry.Count})",
                        SourceIp = NS(r.Source),
                        DestinationIp = r.Destination,
                        DestinationPort = r.DestinationPort,
                        Protocol = "QUIC",
                        Severity = entry.Count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                        Count = entry.Count
                    };
                    return true;
                }

                return false;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R042 error: {ex}");
                return false;
            }
        }

        // ===== R043: SNI / HTTP Host mismatch to same destination =====
        private static bool DetectSniHostMismatch(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                var key = (Src: NS(r.Source), Dst: NS(r.Destination));
                string info = r.Info ?? string.Empty;

                // 1) Capture SNI from TLS/HTTPS/QUIC-like traffic
                bool tlsLike =
                    r.DestinationPort == 443 ||
                    string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase) ||
                    string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase) ||
                    r.IsQuic;

                if (tlsLike && !string.IsNullOrWhiteSpace(r.Sni))
                {
                    _tlsSniByFlow[key] = (r.Sni!, now);
                    BoundDictionary(_tlsSniByFlow, 20_000);
                    return false;
                }

                // 2) When HTTP request appears shortly after to same dst, compare Host vs SNI
                bool httpLike =
                    string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase) ||
                    r.HttpMethod is not null ||
                    info.Contains("HTTP/1.", StringComparison.OrdinalIgnoreCase);
                if (!httpLike) return false;

                if (!_tlsSniByFlow.TryGetValue(key, out var prev))
                    return false;

                if ((now - prev.Ts).TotalSeconds > 120) // 2 min TTL
                    return false;

                var headers = r.HttpRequestHeaders ?? info;
                var m = _httpHostCaptureRx.Match(headers);
                if (!m.Success) return false;
                var host = m.Groups["host"].Value;

                var sniRoot = RootDomain(prev.Sni);
                var hostRoot = RootDomain(host);

                if (string.IsNullOrEmpty(sniRoot) || string.IsNullOrEmpty(hostRoot))
                    return false;

                if (sniRoot.Equals(hostRoot, StringComparison.OrdinalIgnoreCase))
                    return false;

                if (SuppressRepeat(now, "R043", key.Src, key.Dst, r.DestinationPort))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R043",
                    Description = $"SNI/Host mismatch to {key.Dst}: SNI='{prev.Sni}' vs Host='{host}'",
                    SourceIp = key.Src,
                    DestinationIp = key.Dst,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTPS",
                    Severity = SeverityLevel.Medium,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R043 error: {ex}");
                return false;
            }
        }

        // ===== R044: Unusual HTTP methods to Internet =====
        private static bool DetectHttpMethodAnomaly(DateTime now, TrafficRecord r, out DetectionEvent det)
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
                if (IsPrivateIp(r.Destination)) return false;

                // Extract method
                string method = r.HttpMethod
                                ?? (info.Split('\n').FirstOrDefault() ?? string.Empty)
                                       .Split(' ')
                                       .FirstOrDefault()
                                ?? string.Empty;
                method = method.Trim().ToUpperInvariant();
                if (string.IsNullOrEmpty(method)) return false;

                var suspicious = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "CONNECT", "TRACE", "TRACK",
                    "PROPFIND", "PROPPATCH", "MKCOL",
                    "MOVE", "COPY"
                };

                if (!suspicious.Contains(method))
                    return false;

                // CONNECT on typical proxy ports: let existing proxy rules handle
                if (method == "CONNECT" &&
                    (r.DestinationPort is int p) &&
                    (p is 3128 or 8080 or 8000 or 8888 or 1080))
                    return false;

                if (SuppressRepeat(now, "R044", NS(r.Source), r.Destination, r.DestinationPort))
                    return false;

                det = new DetectionEvent
                {
                    RuleId = "R044",
                    Description = $"Unusual HTTP method '{method}' to Internet",
                    SourceIp = NS(r.Source),
                    DestinationIp = r.Destination,
                    DestinationPort = r.DestinationPort,
                    Protocol = "HTTP",
                    Severity = method == "CONNECT" ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex)
            {
                Console.Error.WriteLine($"[RuleEngine] R044 error: {ex}");
                return false;
            }
        }

        // ===== R045: Sparse-header POST to Internet =====
        private static bool DetectSparseHttpPost(DateTime now, TrafficRecord r, out DetectionEvent det)
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
                if (IsPrivateIp(r.Destination)) return false;

                string method = r.HttpMethod
                                ?? (info.Split('\n').FirstOrDefault() ?? string.Empty)
                                       .Split(' ')
                                       .FirstOrDefault()
                                ?? string.Empty;
                if (!string.Equals(method, "POST", StringComparison.OrdinalIgnoreCase))
                    return false;

                string headers = r.HttpRequestHeaders ?? info;
                bool hasHost = _httpHostCaptureRx.IsMatch(headers);
                if (!hasHost) return false; // no Host header at all -> R018 covers that

                bool hasUa = (r.HttpUserAgent?.Length ?? 0) > 0 ||
                             headers.IndexOf("User-Agent:", StringComparison.OrdinalIgnoreCase) >= 0;
                bool hasCt = headers.IndexOf("Content-Type:", StringComparison.OrdinalIgnoreCase) >= 0;

                if (hasUa && hasCt) return false;

                if (SuppressRepeat(now, "R045", NS(r.Source), r.Destination, r.DestinationPort))
                    return false;

                string missing =
                    hasUa && !hasCt ? "Content-Type"
                    : !hasUa && hasCt ? "User-Agent"
                    : "User-Agent & Content-Type";

                det = new DetectionEvent
                {
                    RuleId = "R045",
                    Description = $"Sparse-header HTTP POST to Internet (missing {missing})",
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
                Console.Error.WriteLine($"[RuleEngine] R045 error: {ex}");
                return false;
            }
        }

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
