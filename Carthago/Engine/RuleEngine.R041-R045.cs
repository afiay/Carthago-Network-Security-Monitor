// SPDX-License-Identifier: MIT
// R041-R045: bounded, evidence-driven legacy TLS/QUIC/HTTP detectors.
// Candidate implementation; deferred verification is mandatory.
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static readonly ConcurrentDictionary<(string Src, string Ja4), ConcurrentDictionary<string, DateTime>> _ja4SniFanout = new();

        private sealed class QuicAlpnState
        {
            public int Count;
            public DateTime Last;
            public readonly Dictionary<string, DateTime> LastByFlow = new(StringComparer.Ordinal);
        }

        // Rarity is global per ALPN, but duplicate evidence is scoped to each flow.
        private static readonly ConcurrentDictionary<string, QuicAlpnState> _quicAlpnCounts = new(StringComparer.OrdinalIgnoreCase);

        // Correlate on the observed transport tuple, never on source/destination IPs alone.
        private static readonly ConcurrentDictionary<(string Src, string Dst, int SrcPort, int DstPort), (string Sni, DateTime Ts)> _tlsSniByFlow = new();

        private static bool TryCanonicalLegacyHost(string? raw, out string host)
        {
            host = string.Empty;
            if (string.IsNullOrWhiteSpace(raw) || raw.Length > 260) return false;
            var value = raw.Trim().TrimEnd('.');
            if (value.Any(char.IsControl) || value.Contains('@') || value.Contains('/') || value.Contains('['))
                return false;
            int colon = value.LastIndexOf(':');
            if (colon >= 0)
            {
                if (value.IndexOf(':') != colon || !int.TryParse(value.Substring(colon + 1), out int port)
                    || port is < 1 or > 65535) return false;
                value = value.Substring(0, colon);
            }
            if (value.Length is < 4 or > 253 || !value.Contains('.') || IPAddress.TryParse(value, out _))
                return false;
            foreach (var label in value.Split('.'))
            {
                if (label.Length is < 1 or > 63 ||
                    !Regex.IsMatch(label, @"\A[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\z",
                        RegexOptions.CultureInvariant))
                    return false;
            }
            host = value.ToLowerInvariant();
            return true;
        }

        private static bool IsObservedLegacyTls(TrafficRecord r)
            => !r.IsQuic && (string.Equals(r.Protocol, "TLS", StringComparison.OrdinalIgnoreCase)
                || string.Equals(r.Protocol, "HTTPS", StringComparison.OrdinalIgnoreCase));

        private static bool IsObservedLegacyQuic(TrafficRecord r)
            => string.Equals(r.Protocol, "QUIC", StringComparison.OrdinalIgnoreCase)
                || (r.IsQuic && string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase));

        private static bool IsObservedLegacyHttpRequest(TrafficRecord r)
            => !r.IsQuic && r.Length > 0 && !string.IsNullOrWhiteSpace(r.HttpMethod)
                && (string.Equals(r.Protocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                    || (string.Equals(r.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                        && string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase)))
                && (string.IsNullOrWhiteSpace(r.ApplicationService)
                    || string.Equals(r.ApplicationService, "HTTP", StringComparison.OrdinalIgnoreCase));

        private static bool HasLegacyInternetEndpoints(TrafficRecord r)
            => r.Length > 0 && IsAttributablePrivateHostIp(r.Source)
                && IsPublicLegacyEgressIp(r.Destination)
                && IPAddress.TryParse(r.Source, out _)
                && IPAddress.TryParse(r.Destination, out _)
                && r.DestinationPort is int port && port is >= 1 and <= 65535;

        // R041: eight distinct valid SNIs per (source, JA4) in 60 seconds.
        private static bool DetectJa4FanoutSweep(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r)
                    || !(IsObservedLegacyTls(r) || IsObservedLegacyQuic(r))
                    || string.IsNullOrWhiteSpace(r.Ja4)
                    || !Regex.IsMatch(r.Ja4, @"\A[A-Za-z0-9_-]{8,128}\z", RegexOptions.CultureInvariant)
                    || !TryCanonicalLegacyHost(r.Sni, out var sni)) return false;

                const int window = 60, threshold = 8;
                var key = (Src: IPAddress.Parse(r.Source!).ToString(), Ja4: r.Ja4!);
                BoundDictionary(_ja4SniFanout, 20000);
                var map = _ja4SniFanout.GetOrAdd(key,
                    _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
                int distinct;
                lock (map)
                {
                    // Out-of-order evidence cannot roll back or manufacture a fan-out.
                    if (map.Values.Any(ts => ts > now)) return false;
                    var cutoff = now.AddSeconds(-window);
                    foreach (var old in map.Where(kv => kv.Value < cutoff).Select(kv => kv.Key).ToArray())
                        map.TryRemove(old, out _);
                    if (map.TryGetValue(sni, out var previous) && previous == now) return false;
                    map[sni] = now;
                    distinct = map.Count;
                    if (distinct < threshold) return false;
                    map.Clear(); // Complete the window even if alert cooldown suppresses it.
                }
                if (SuppressRepeat(now, "R041", key.Src, null, null)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R041", Description = $"JA4 fan-out across {distinct} distinct SNI hosts in {window}s",
                    SourceIp = key.Src, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = NP(r.Protocol), Severity = SeverityLevel.High,
                    Count = distinct, WindowSeconds = window
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R041 error: {ex.GetType().Name}"); }
            return false;
        }

        // R042: first three distinct observed uncommon-ALPN flow events in a six-hour epoch.
        private static bool DetectUncommonQuicAlpn(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyQuic(r)
                    || string.IsNullOrWhiteSpace(r.QuicAlpn)) return false;
                string alpn = r.QuicAlpn.Trim().ToLowerInvariant();
                if (!Regex.IsMatch(alpn, @"\A[a-z0-9][a-z0-9._/-]{0,63}\z", RegexOptions.CultureInvariant)
                    || alpn.StartsWith("h3", StringComparison.Ordinal)
                    || alpn.StartsWith("hq-", StringComparison.Ordinal)
                    || alpn == "http/3") return false;

                BoundDictionary(_quicAlpnCounts, 5000);
                var state = _quicAlpnCounts.GetOrAdd(alpn, _ => new QuicAlpnState());
                int count;
                string flow = $"{IPAddress.Parse(r.Source!).ToString()}|{IPAddress.Parse(r.Destination!).ToString()}|{r.DestinationPort}";
                lock (state)
                {
                    if (state.Count > 0 && now < state.Last) return false;
                    if (state.Count > 0 && now - state.Last > TimeSpan.FromHours(6))
                    {
                        state.Count = 0;
                        state.LastByFlow.Clear();
                    }
                    if (state.LastByFlow.TryGetValue(flow, out var seen) && now <= seen) return false;
                    state.LastByFlow[flow] = now;
                    if (state.LastByFlow.Count > 256)
                    {
                        foreach (var old in state.LastByFlow.OrderBy(kv => kv.Value)
                            .Take(state.LastByFlow.Count - 256).Select(kv => kv.Key).ToArray())
                            state.LastByFlow.Remove(old);
                    }
                    state.Count++;
                    state.Last = now;
                    count = state.Count;
                }
                if (count > 3 || SuppressRepeat(now, "R042", r.Source!, r.Destination, r.DestinationPort))
                    return false;
                det = new DetectionEvent
                {
                    RuleId = "R042", Description = "Uncommon QUIC ALPN observed (validated protocol evidence)",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "QUIC", Severity = count == 1 ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = count
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R042 error: {ex.GetType().Name}"); }
            return false;
        }

        // R043: correlate actual TLS SNI with an observed HTTP request on the same tuple.
        private static bool DetectSniHostMismatch(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r)
                    || r.SourcePort is not int sourcePort || sourcePort is < 1 or > 65535
                    || r.DestinationPort is not int destPort) return false;
                var key = (Src: IPAddress.Parse(r.Source!).ToString(),
                    Dst: IPAddress.Parse(r.Destination!).ToString(), SrcPort: sourcePort, DstPort: destPort);
                if (IsObservedLegacyTls(r) && TryCanonicalLegacyHost(r.Sni, out var sni))
                {
                    if (_tlsSniByFlow.TryGetValue(key, out var existing) && now < existing.Ts)
                        return false;
                    BoundDictionary(_tlsSniByFlow, 20000);
                    _tlsSniByFlow[key] = (sni, now);
                    return false;
                }
                if (!IsObservedLegacyHttpRequest(r)
                    || string.Equals(r.HttpMethod, "CONNECT", StringComparison.OrdinalIgnoreCase)
                    || !_tlsSniByFlow.TryGetValue(key, out var prev)
                    || now <= prev.Ts || now - prev.Ts > TimeSpan.FromSeconds(120))
                    return false;

                string? observedHost = r.HttpHost;
                if (!string.IsNullOrWhiteSpace(r.HttpRequestHeaders))
                {
                    var matches = _httpHostCaptureRx.Matches(r.HttpRequestHeaders);
                    if (matches.Count > 1) return false;
                    if (matches.Count == 1)
                    {
                        string headerHost = matches[0].Groups["host"].Value;
                        if (!TryCanonicalLegacyHost(headerHost, out var normalizedHeader)) return false;
                        if (observedHost != null &&
                            (!TryCanonicalLegacyHost(observedHost, out var normalizedField)
                                || normalizedField != normalizedHeader)) return false;
                        observedHost = normalizedHeader;
                    }
                }
                if (!TryCanonicalLegacyHost(observedHost, out var host)
                    || string.Equals(RootDomain(prev.Sni), RootDomain(host), StringComparison.OrdinalIgnoreCase))
                    return false;

                _tlsSniByFlow.TryRemove(key, out _);
                if (SuppressRepeat(now, "R043", key.Src, key.Dst, key.DstPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R043", Description = "TLS SNI and HTTP Host disagree on a correlated flow",
                    SourceIp = key.Src, DestinationIp = key.Dst, DestinationPort = key.DstPort,
                    Protocol = "HTTPS", Severity = SeverityLevel.Medium, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R043 error: {ex.GetType().Name}"); }
            return false;
        }

        // R044: only structured HTTP requests, never Info prose or unrelated protocols.
        private static bool DetectHttpMethodAnomaly(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyHttpRequest(r)) return false;
                string method = r.HttpMethod!.Trim().ToUpperInvariant();
                if (method is not ("CONNECT" or "TRACE" or "TRACK" or "PROPFIND"
                    or "PROPPATCH" or "MKCOL" or "MOVE" or "COPY")) return false;
                if (method == "CONNECT" && r.DestinationPort is 3128 or 8080 or 8000 or 8888 or 1080)
                    return false;
                if (SuppressRepeat(now, "R044", r.Source!, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R044", Description = $"Unusual structured HTTP method {method} to public destination",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = method == "CONNECT" ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R044 error: {ex.GetType().Name}"); }
            return false;
        }

        // R045: absent headers are evidence only when the captured header block is complete.
        private static bool DetectSparseHttpPost(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyHttpRequest(r)
                    || !string.Equals(r.HttpMethod, "POST", StringComparison.OrdinalIgnoreCase)
                    || string.IsNullOrWhiteSpace(r.HttpRequestHeaders)) return false;
                string headers = r.HttpRequestHeaders;
                if (headers.Length > 16384 ||
                    !(headers.EndsWith("\r\n\r\n", StringComparison.Ordinal)
                        || headers.EndsWith("\n\n", StringComparison.Ordinal))) return false;
                var hosts = Regex.Matches(headers, @"(?im)^Host\s*:\s*(?<host>[^\r\n]+)\r?$");
                if (hosts.Count != 1 ||
                    !TryCanonicalLegacyHost(hosts[0].Groups["host"].Value, out var headerHost)
                    || (r.HttpHost != null &&
                        (!TryCanonicalLegacyHost(r.HttpHost, out var fieldHost)
                            || fieldHost != headerHost))) return false;

                bool hasUa = !string.IsNullOrWhiteSpace(r.HttpUserAgent)
                    || Regex.IsMatch(headers, @"(?im)^User-Agent\s*:\s*\S");
                bool hasCt = Regex.IsMatch(headers, @"(?im)^Content-Type\s*:\s*\S");
                if (hasUa && hasCt) return false;
                if (SuppressRepeat(now, "R045", r.Source!, r.Destination, r.DestinationPort)) return false;
                string missing = hasUa ? "Content-Type" : hasCt ? "User-Agent" : "User-Agent and Content-Type";
                det = new DetectionEvent
                {
                    RuleId = "R045", Description = $"Complete HTTP POST header block lacks {missing}",
                    SourceIp = r.Source, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = SeverityLevel.Low, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R045 error: {ex.GetType().Name}"); }
            return false;
        }
    }
}
