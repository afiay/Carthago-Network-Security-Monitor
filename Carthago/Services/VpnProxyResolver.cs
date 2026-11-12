// File: Services/VpnProxyResolver.cs
// SPDX-License-Identifier: MIT

using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace Carthago.Services
{
    // ===== Result DTO (kept backward-compatible) =====
    public sealed class VpnProxyResult
    {
        public bool IsVpn { get; set; }
        public bool IsProxy { get; set; }
        public string NetworkType { get; set; } = "Unknown";

        // Local process and port hints are not remote IP identity.
        public bool LocalVpnProcessHint { get; set; }
        public bool VpnPortHint { get; set; }
        public bool IsHosting { get; set; }
        public bool IsResidential { get; set; }
        public int Confidence { get; set; } // 0–100
        public string[] Reasons { get; set; } = Array.Empty<string>();

        public string? Organization { get; set; }
        public string? Asn { get; set; }
        public string? Country { get; set; }
        public string? ReverseDns { get; set; }
        public string? Registry { get; set; }

        // Engine diagnostics (optional)
        public Dictionary<string, double>? SignalScores { get; set; }
    }

    // ===== Optional hints from your pipeline (TrafficRecord etc.) =====
    public sealed class VpnContext
    {
        public required string Ip { get; init; }
        public bool AllowRdap { get; init; } = true;
        public string? Sni { get; init; }         // TLS SNI if present
        public int? DstPort { get; init; }        // Destination port from flow
        public string? Protocol { get; init; }    // "TCP"/"UDP"/...
        public string? Ja4h { get; init; }        // TLS client/handshake fp (JA4/JA4H)
        public string? Ja4x { get; init; }        // X.509-derived fp
        public string? ProcessName { get; init; } // From WindowsProcessResolver
        public int? AbuseScore { get; init; }     // From AbuseIPDB check if you have it
    }

    // ===== Public facade (keeps your API) =====
    public static class VpnProxyResolver
    {
        public static TimeSpan CacheTtl { get; set; } = TimeSpan.FromHours(6);
        public static bool EnableReverseDns { get; set; } = true;

        // Runtime configuration (weights can be tuned/learned)
        private static readonly Dictionary<string, double> Weights = new(StringComparer.Ordinal)
        {
            ["rdap.hosting"] = 1.2,
            ["rdap.resi"] = -0.8,
            ["rdns.vpn"] = 1.3,
            ["rdns.proxy"] = 0.9,
            ["rdns.resi"] = -0.6,
            ["port.proto"] = 0.7,
            ["ja4.client.vpn"] = 1.5,
            ["ja4.server.vpn"] = 1.5,
            ["rdns.cdn"] = 0.1,
            ["proc.vpn"] = 1.8,
            ["abuse.score"] = 0.6,
        };

        private static readonly InferenceEngine Engine = new(Weights, CacheTtl,
            new IVpnSignal[]
            {
                new RdapSignal(),
                new ReverseDnsSignal(() => EnableReverseDns),
                new PortProtocolSignal(),
                new Ja4Signal(),
                new ProcessNameSignal(),
                new AbuseScoreSignal(),
            });

        // Legacy signature
        public static VpnProxyResult CheckIp(string ip) =>
            CheckIpAsync(ip).GetAwaiter().GetResult();

        // Upgraded (non-breaking) — you can optionally pass hints
        public static Task<VpnProxyResult> CheckIpAsync(string ip, CancellationToken ct = default) =>
            Engine.ClassifyAsync(new VpnContext { Ip = ip }, ct);

        public static Task<VpnProxyResult> CheckAsync(VpnContext ctx, CancellationToken ct = default) =>
            Engine.ClassifyAsync(ctx, ct);
    }

    // ===== Generic signal interface =====
    internal interface IVpnSignal
    {
        string Name { get; } // e.g., "rdap", "rdns", "ja4"
        Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct);
        TimeSpan Ttl { get; }
    }

    internal sealed record SignalScore(string Key, double Score, string Reason,
        string? Organization = null, string? Asn = null, string? Country = null,
        string? Registry = null, string? ReverseDns = null);

    // ===== Inference engine (sigmoid blend + reasons) =====
    internal sealed class InferenceEngine
    {
        private readonly Dictionary<string, double> _weights;
        private readonly TimeSpan _ttl;
        private readonly IVpnSignal[] _signals;

        private sealed class CacheEntry
        {
            public IReadOnlyList<SignalScore> Signals = Array.Empty<SignalScore>();
            public DateTimeOffset Expiry;
        }
        private readonly ConcurrentDictionary<string, CacheEntry> _cache = new(StringComparer.Ordinal);
        private const int CacheCapacity = 8192;

        public InferenceEngine(Dictionary<string, double> weights, TimeSpan ttl, IVpnSignal[] signals)
        {
            _weights = weights;
            _ttl = ttl;
            _signals = signals;
        }

        public async Task<VpnProxyResult> ClassifyAsync(VpnContext ctx, CancellationToken ct)
        {
            if (!IPAddress.TryParse(ctx.Ip, out var ip))
                return Final("Invalid", 0, "Invalid IP");

            if (EndpointIpEnrichment.Classify(ip.ToString()) != "Public")
                return Final("Bogon", 0, "Non-public or special-use address");

            ct.ThrowIfCancellationRequested();
            // Only stable endpoint metadata may be cached. Port, process, JA4
            // and reputation hints are evaluated for the current connection.
            var tasks = _signals.Select(s => EvaluateSignalAsync(s, ctx, ip, ct)).ToArray();
            await Task.WhenAll(tasks).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();

            // combine scores
            var contributions = new List<SignalScore>(32);
            foreach (var t in tasks)
                contributions.AddRange(t.Result);

            double z = 0;
            var reasons = new List<string>(8);
            var perKey = new Dictionary<string, double>(StringComparer.Ordinal);

            foreach (var c in contributions)
            {
                double w = _weights.TryGetValue(c.Key, out var ww) ? ww : 0.0;
                double v = w * c.Score;
                if (Math.Abs(v) < double.Epsilon) continue;
                // Only endpoint-specific evidence contributes to remote classification.
                if (c.Key.StartsWith("rdap.", StringComparison.Ordinal)
                    || c.Key.StartsWith("rdns.", StringComparison.Ordinal)
                    || c.Key == "ja4.server.vpn")
                    z += v;
                perKey[c.Key] = perKey.TryGetValue(c.Key, out var prev) ? prev + v : v;
                reasons.Add($"{c.Key}: {c.Reason} (x{w:0.##})");
            }

            // Sigmoid → [0..1]
            double p = 1.0 / (1.0 + Math.Exp(-z));
            bool vpnLean = perKey.ContainsKey("ja4.server.vpn") || perKey.ContainsKey("rdns.vpn");
            bool proxyLean = perKey.ContainsKey("rdns.proxy");
            // A neutral sigmoid is not 50% evidence that an address is a VPN.
            int conf = vpnLean || proxyLean ? (int)Math.Round(p * 100) : 0;
            bool hosting = perKey.Keys.Any(k => k.StartsWith("rdap.hosting"));
            bool resi = perKey.Keys.Any(k => k.StartsWith("rdns.resi") || k.StartsWith("rdap.resi"));

            bool isVpn = vpnLean && conf >= 60;
            bool isProxy = proxyLean && conf >= 55;
            var netType = isVpn ? "VPN"
                       : isProxy ? "Proxy"
                       : perKey.ContainsKey("rdns.cdn") ? "CDN"
                       : hosting ? "Hosting/DC"
                       : resi ? "Residential/Mobile"
                       : "Unknown";

            var result = new VpnProxyResult
            {
                IsVpn = isVpn,
                IsProxy = isProxy,
                LocalVpnProcessHint = perKey.ContainsKey("proc.vpn"),
                VpnPortHint = perKey.ContainsKey("port.proto"),
                IsHosting = hosting,
                IsResidential = resi,
                NetworkType = netType,
                Confidence = conf,
                Reasons = reasons.Distinct().ToArray(),
                SignalScores = perKey
            };

            // Metadata travels with its own signal, never through shared IP state.
            foreach (var evidence in contributions)
            {
                result.Organization ??= evidence.Organization;
                result.Asn ??= evidence.Asn;
                result.Country ??= evidence.Country;
                result.Registry ??= evidence.Registry;
                result.ReverseDns ??= evidence.ReverseDns;
            }
            return result;

            static VpnProxyResult Final(string type, int conf, string reason)
            {
                return new VpnProxyResult
                {
                    NetworkType = type,
                    Confidence = conf,
                    Reasons = new[] { reason }
                };
            }
        }

        private async Task<IReadOnlyList<SignalScore>> EvaluateSignalAsync(
            IVpnSignal signal, VpnContext ctx, IPAddress ip, CancellationToken ct)
        {
            if (signal.Name == "rdap" && !ctx.AllowRdap)
                return Array.Empty<SignalScore>();
            if (signal is ReverseDnsSignal ptr && !ptr.Enabled)
                return Array.Empty<SignalScore>();

            bool endpointOnly = signal.Name is "rdap" or "rdns";
            if (!endpointOnly)
                return await signal.EvaluateAsync(ctx, ct).ConfigureAwait(false);

            string key = signal.Name + ":" + EndpointIpEnrichment.Normalize(ip);
            if (_cache.TryGetValue(key, out var hit) && hit.Expiry > DateTimeOffset.UtcNow)
                return hit.Signals;

            var signals = await signal.EvaluateAsync(ctx, ct).ConfigureAwait(false);
            ct.ThrowIfCancellationRequested();
            // Empty/failed queries are not cached as affirmative evidence.
            if (signals.Count > 0)
            {
                if (_cache.Count >= CacheCapacity) _cache.Clear();
                var ttl = signal.Ttl < _ttl ? signal.Ttl : _ttl;
                _cache[key] = new CacheEntry { Signals = signals.ToArray(), Expiry = DateTimeOffset.UtcNow.Add(ttl) };
            }
            return signals;
        }
    }

    // ===== Signals =====

    // RDAP/WHOIS (your existing WhoisResolver)
    internal sealed class RdapSignal : IVpnSignal
    {
        public string Name => "rdap";
        public TimeSpan Ttl => TimeSpan.FromHours(6);

        // minimal corpora (extend at runtime with your feeds)
        private static readonly string[] Hosting = new[]
        {
            "aws","amazon","ec2","cloudfront","azure","cloudapp","google","gcp","googleusercontent","1e100.net",
            "digitalocean","linode","hetzner","ovh","ovhcloud","contabo","vultr","scaleway","leaseweb","akamai","fastly",
            "cloudflare","vercel","netlify","server","hosting","colo","datacenter","baremetal","hivelocity","ionos","m247","choopa"
        };
        private static readonly string[] Residential = new[]
        {
            "comcast","xfinity","charter","spectrum","cox","att","verizon","rogers","shaw","bell","virgin media","bt","sky",
            "o2","vodafone","orange","telefonica","movistar","telia","telenor","tele2","elisa","dna","kpn","proximus","ziggo",
            "telmex","claro","optus","telstra","spark","eir","tim","fastweb","sfr","free sas","yettel","deutsche telekom"
        };

        public async Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var scores = new List<SignalScore>(3);
            try
            {
                string raw = await WhoisResolver.LookupRawAsync(ctx.Ip, ct).ConfigureAwait(false);
                if (string.IsNullOrWhiteSpace(raw) || raw.StartsWith("WHOIS lookup failed:", StringComparison.OrdinalIgnoreCase))
                    return scores;
                var org = WhoisResolver.GetOrganization(raw)?.Trim();
                var asn = WhoisResolver.GetASN(raw)?.Trim();
                var cc = WhoisResolver.GetCountry(raw)?.Trim();
                var reg = WhoisResolver.GetRegistrar(raw)?.Trim();

                var text = $"{org} {asn}".ToLowerInvariant();

                if (ContainsAny(text, Hosting))
                    scores.Add(new("rdap.hosting", +1.0, $"Org/ASN '{org ?? asn}' looks like hosting/DC"));
                if (ContainsAny(text, Residential))
                    scores.Add(new("rdap.resi", -1.0, $"Org/ASN '{org ?? asn}' looks residential/mobile"));

                if (org is not null || asn is not null || cc is not null || reg is not null)
                    scores.Add(new("metadata.rdap", 0, "RDAP metadata", org, asn, cc, reg));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { /* no RDAP evidence */ }

            return scores;
        }

        private static bool ContainsAny(string hay, IEnumerable<string> kws)
        {
            if (string.IsNullOrWhiteSpace(hay)) return false;
            hay = hay.ToLowerInvariant();
            foreach (var kw in kws) if (hay.Contains(kw)) return true;
            return false;
        }
    }

    // Reverse DNS (PTR) patterning
    internal sealed class ReverseDnsSignal : IVpnSignal
    {
        public string Name => "rdns";
        public TimeSpan Ttl => TimeSpan.FromHours(6);
        private readonly Func<bool> _enabled;

        public ReverseDnsSignal(Func<bool> enabled) => _enabled = enabled;
        internal bool Enabled => _enabled();

        private static readonly string[] VpnBrands = new[]
        {
            "nordvpn","mullvad","expressvpn","protonvpn","surfshark","windscribe","cyberghost","torguard","ivpn","airvpn",
            "perfect-privacy","hidemyass","hmai","psiphon"
        };

        private static readonly string[] ProxyCdn = new[]
        {
            "proxy","revproxy","squid","nginxproxy"
        };

        private static readonly string[] ResidentialTokens = new[]
        {
            "dyn","pool","cable","fiber","dsl","pppoe","cust","subnet","ip-","user-","客户","cliente" // mixed locales
        };

        private static readonly Regex TorExitRx = new(@"(^|\.)(tor(exit|node)|tor\-exit)\.", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public async Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var outp = new List<SignalScore>(3);
            if (!_enabled()) return outp;

            try
            {
                var entry = await Dns.GetHostEntryAsync(ctx.Ip).WaitAsync(TimeSpan.FromSeconds(2), ct).ConfigureAwait(false);
                var rdns = entry?.HostName?.Trim().ToLowerInvariant();
                if (string.IsNullOrWhiteSpace(rdns)) return outp;

                outp.Add(new("metadata.rdns", 0, "PTR metadata", ReverseDns: rdns));

                if (TorExitRx.IsMatch(rdns))
                    outp.Add(new("rdns.vpn", +1.2, $"PTR '{rdns}' resembles Tor/VPN naming"));

                if (ContainsAny(rdns, VpnBrands))
                    outp.Add(new("rdns.vpn", +1.0, $"PTR contains VPN brand ({rdns})"));

                if (ContainsAny(rdns, ProxyCdn))
                    outp.Add(new("rdns.proxy", +0.8, $"PTR suggests proxy service ({rdns})"));
                if (ContainsAny(rdns, new[] { "edge", "cdn", "cache", "anycast" }))
                    outp.Add(new("rdns.cdn", +0.5, $"PTR suggests CDN/edge infrastructure ({rdns})"));

                if (ContainsAny(rdns, ResidentialTokens))
                    outp.Add(new("rdns.resi", -0.7, $"PTR looks residential-ish ({rdns})"));
            }
            catch (OperationCanceledException) when (ct.IsCancellationRequested) { throw; }
            catch { /* no PTR or timeout */ }

            return outp;

            static bool ContainsAny(string hay, IEnumerable<string> kws)
            {
                if (string.IsNullOrWhiteSpace(hay)) return false;
                hay = hay.ToLowerInvariant();
                foreach (var kw in kws) if (hay.Contains(kw)) return true;
                return false;
            }
        }
    }

    // Protocol/port heuristics (conservative)
    internal sealed class PortProtocolSignal : IVpnSignal
    {
        public string Name => "port";
        public TimeSpan Ttl => TimeSpan.FromMinutes(30);

        // Not authoritative; just weak priors
        private static readonly HashSet<int> VpnPorts = new(new[] { 1194, 500, 4500, 1701, 1723, 51820 }); // OpenVPN, TLS-tunnel, IKEv2/IPsec, L2TP, PPTP, WireGuard

        public Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var list = new List<SignalScore>(1);
            if (ctx.DstPort.HasValue && VpnPorts.Contains(ctx.DstPort.Value))
                list.Add(new("port.proto", +0.5, $"DstPort {ctx.DstPort} is commonly used by VPNs"));
            return Task.FromResult<IReadOnlyList<SignalScore>>(list);
        }
    }

    // JA4/JA4H/JA4X hooks (seed with your own intel)
    internal sealed class Ja4Signal : IVpnSignal
    {
        public string Name => "ja4";
        public TimeSpan Ttl => TimeSpan.FromHours(6);

        // Provide your own known fingerprints (prefix matches allowed)
        private static readonly string[] KnownVpnJa4h = Array.Empty<string>(); // e.g., "t13d1516h2_8da2_..."
        private static readonly string[] KnownVpnJa4x = Array.Empty<string>(); // cert-derived fingerprints

        public Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var list = new List<SignalScore>(1);
            if (!string.IsNullOrWhiteSpace(ctx.Ja4h) && KnownVpnJa4h.Any(fp => ctx.Ja4h.StartsWith(fp, StringComparison.OrdinalIgnoreCase)))
                list.Add(new("ja4.client.vpn", +1.2, "JA4H matches known VPN client fp"));

            if (!string.IsNullOrWhiteSpace(ctx.Ja4x) && KnownVpnJa4x.Any(fp => ctx.Ja4x.StartsWith(fp, StringComparison.OrdinalIgnoreCase)))
                list.Add(new("ja4.server.vpn", +1.0, "JA4X matches VPN server cert fp"));

            return Task.FromResult<IReadOnlyList<SignalScore>>(list);
        }
    }

    // Endpoint process hints (when running on endpoint)
    internal sealed class ProcessNameSignal : IVpnSignal
    {
        public string Name => "proc";
        public TimeSpan Ttl => TimeSpan.FromMinutes(10);

        private static readonly string[] VpnProcs = new[]
        {
            "openvpn","openvpnserv","wireguard","wireguardtun","wg-quick","nordvpn","protonvpn","expressvpn","windscribe","surfshark","mullvad",
            "pia-service","ivpn","torguard","cyberghost"
        };

        internal static bool IsVpnProcess(string? processName)
        {
            var p = (processName ?? "").Trim();
            if (p.EndsWith(".exe", StringComparison.OrdinalIgnoreCase)) p = p[..^4];
            return VpnProcs.Contains(p, StringComparer.OrdinalIgnoreCase);
        }

        public Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var list = new List<SignalScore>(1);
            if (IsVpnProcess(ctx.ProcessName))
                list.Add(new("proc.vpn", +1.5, $"Local process '{ctx.ProcessName}' looks like a VPN client"));
            return Task.FromResult<IReadOnlyList<SignalScore>>(list);
        }
    }

    // Abuse score as light proxy signal (don’t over-weight)
    internal sealed class AbuseScoreSignal : IVpnSignal
    {
        public string Name => "abuse";
        public TimeSpan Ttl => TimeSpan.FromHours(12);

        public Task<IReadOnlyList<SignalScore>> EvaluateAsync(VpnContext ctx, CancellationToken ct)
        {
            var list = new List<SignalScore>(1);
            if (ctx.AbuseScore is int s && s >= 50)
                list.Add(new("abuse.score", (s / 100.0), $"AbuseIPDB score {s}"));
            return Task.FromResult<IReadOnlyList<SignalScore>>(list);
        }
    }
}
