// SPDX-License-Identifier: MIT
// R046-R049: evidence-driven egress, HTTP and TLS heuristics.
// CANDIDATE — UNVERIFIED. No rule enablement, confidence or policy changes.
using System;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Models;

namespace Carthago.Services
{
    public static partial class RuleEngine
    {
        private static bool DetectUnauthorizedVpnEgress(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r)
                    || !string.Equals(r.Protocol, "UDP", StringComparison.OrdinalIgnoreCase)
                    || r.DestinationPort is not int port
                    || port is not (500 or 4500 or 1701 or 1194 or 51820 or 51821 or 443)
                    || r.IsVpn == false) return false;

                // UDP/443, IPsec and tunnel ports also carry legitimate applications.
                // Require positive protocol classification; port membership alone is not evidence.
                bool vpnObserved = r.IsVpn == true
                    || (r.ApplicationService != null
                        && Regex.IsMatch(r.ApplicationService,
                            @"\A(?:IKE|IPsec|L2TP|OpenVPN|WireGuard|VPN)\z",
                            RegexOptions.IgnoreCase | RegexOptions.CultureInvariant));
                if (!vpnObserved) return false;

                string src = IPAddress.Parse(r.Source!).ToString();
                string dst = IPAddress.Parse(r.Destination!).ToString();
                string key = $"R046:{src}:{dst}:{port}";
                BoundDictionary(_packetTimes, 20000);
                var samples = _packetTimes.GetOrAdd(key, _ => new System.Collections.Generic.List<DateTime>(4));
                lock (samples)
                {
                    // Keep the original first-three-per-minute candidate budget.
                    samples.RemoveAll(t => t < now.AddSeconds(-60));
                    if (samples.Count > 0 && now <= samples[samples.Count - 1]) return false;
                    if (samples.Count >= 3) return false;
                    samples.Add(now);
                }
                if (SuppressRepeat(now, "R046", src, dst, port)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R046",
                    Description = $"VPN-classified UDP/{port} egress to public destination (authorization not established)",
                    SourceIp = src, DestinationIp = dst, DestinationPort = port,
                    Protocol = "UDP", Severity = SeverityLevel.Medium, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R046 error: {ex.GetType().Name}"); }
            return false;
        }

        private static bool TryObservedIpHost(TrafficRecord r, out string destination)
        {
            destination = string.Empty;
            if (!IPAddress.TryParse(r.Destination, out var destIp)) return false;
            destination = destIp.ToString();
            string? host = r.HttpHost;
            if (!string.IsNullOrWhiteSpace(r.HttpRequestHeaders))
            {
                var hosts = Regex.Matches(r.HttpRequestHeaders, @"(?im)^Host[ \t]*:[ \t]*(?<host>[^\r\n]+)\r?$");
                if (hosts.Count > 1) return false;
                if (hosts.Count == 1)
                {
                    var headerHost = hosts[0].Groups["host"].Value.Trim();
                    if (host != null && !string.Equals(host.Trim(), headerHost, StringComparison.OrdinalIgnoreCase))
                        return false;
                    host = headerHost;
                }
            }
            if (string.IsNullOrWhiteSpace(host)) return false;
            string literal = host.Trim();
            if (literal.StartsWith("[", StringComparison.Ordinal))
            {
                int close = literal.IndexOf(']');
                if (close < 0) return false;
                string suffix = literal.Substring(close + 1);
                if (suffix.Length > 0 && (!suffix.StartsWith(":", StringComparison.Ordinal)
                    || !int.TryParse(suffix.Substring(1), out int bracketPort)
                    || bracketPort is < 1 or > 65535)) return false;
                literal = literal.Substring(1, close - 1);
            }
            else if (!IPAddress.TryParse(literal, out _) && literal.Count(c => c == ':') == 1)
            {
                int colon = literal.LastIndexOf(':');
                if (!int.TryParse(literal.Substring(colon + 1), out int hostPort)
                    || hostPort is < 1 or > 65535) return false;
                literal = literal.Substring(0, colon);
            }
            return IPAddress.TryParse(literal, out var parsed) && parsed.Equals(destIp);
        }

        private static bool DetectHttpBasicAuthToIp(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyHttpRequest(r)
                    || !TryObservedIpHost(r, out var destination)
                    || string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                    || r.HttpRequestHeaders.Length > 16384) return false;

                // Only the captured request header, never Info prose or a response.
                // Do not decode, retain, interpolate or log the credential.
                var credentials = Regex.Matches(r.HttpRequestHeaders,
                    @"(?im)^Authorization[ \t]*:[ \t]*Basic[ \t]+[A-Za-z0-9+/]{8,}={0,2}[ \t]*\r?$");
                if (credentials.Count != 1) return false;
                string src = IPAddress.Parse(r.Source!).ToString();
                if (SuppressRepeat(now, "R047", src, destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R047", Description = "Observed HTTP Basic authentication to IP-literal Host (credential exposure risk)",
                    SourceIp = src, DestinationIp = destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = SeverityLevel.High, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R047 error: {ex.GetType().Name}"); }
            return false;
        }

        private static bool DetectAlternateDoHPatterns(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyHttpRequest(r)
                    || r.DestinationPort != 443
                    || string.IsNullOrWhiteSpace(r.HttpUri)
                    || r.HttpUri.Length > 4096
                    || !TryCanonicalLegacyHost(r.HttpHost, out var host)) return false;

                if (!string.IsNullOrWhiteSpace(r.HttpRequestHeaders))
                {
                    var hosts = Regex.Matches(r.HttpRequestHeaders, @"(?im)^Host[ \t]*:[ \t]*(?<host>[^\r\n]+)\r?$");
                    if (hosts.Count > 1) return false;
                    if (hosts.Count == 1 && (!TryCanonicalLegacyHost(hosts[0].Groups["host"].Value, out var observed)
                        || !string.Equals(observed, host, StringComparison.Ordinal))) return false;
                }

                bool provider = host == "dns.google" || host == "cloudflare-dns.com"
                    || host == "mozilla.cloudflare-dns.com" || host.StartsWith("doh.", StringComparison.Ordinal);
                if (!provider) return false;
                string method = r.HttpMethod!.Trim().ToUpperInvariant();
                string uri = r.HttpUri;
                bool getDns = method == "GET"
                    && Regex.IsMatch(uri, @"\A/dns-query\?[^#\s]*\bdns=[A-Za-z0-9_-]{8,}={0,2}(?:&[^#\s]*)?\z",
                        RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
                bool json = !string.IsNullOrWhiteSpace(r.HttpRequestHeaders)
                    && Regex.IsMatch(r.HttpRequestHeaders, @"(?im)^(?:Accept|Content-Type)[ \t]*:[ \t]*application/dns-json(?:[ \t]*;[^\r\n]*)?\r?$");
                bool jsonQuery = method == "GET" && uri.StartsWith("/resolve?name=", StringComparison.OrdinalIgnoreCase) && json;
                bool jsonPost = method == "POST" && uri == "/dns-query" && json;
                if (!(getDns || jsonQuery || jsonPost)) return false;

                string src = IPAddress.Parse(r.Source!).ToString();
                BoundDictionary(_altDohSeenBySrc, 20000);
                var observations = _altDohSeenBySrc.GetOrAdd(src, _ => new System.Collections.Generic.List<DateTime>(8));
                lock (observations)
                {
                    observations.RemoveAll(t => t < now.AddSeconds(-120));
                    if (observations.Count > 0 && now <= observations[observations.Count - 1]) return false;
                    if (observations.Count >= 128) observations.RemoveAt(0);
                    observations.Add(now);
                }
                if (SuppressRepeat(now, "R048", src, r.Destination, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R048", Description = "Structured alternate DNS-over-HTTPS request to a DNS endpoint",
                    SourceIp = src, DestinationIp = r.Destination, DestinationPort = r.DestinationPort,
                    Protocol = "HTTP", Severity = SeverityLevel.Low, Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R048 error: {ex.GetType().Name}"); }
            return false;
        }

        private static bool DetectSuspiciousSniShape(DateTime now, TrafficRecord r, out DetectionEvent det)
        {
            det = null!;
            try
            {
                if (!HasLegacyInternetEndpoints(r) || !IsObservedLegacyTls(r)
                    || string.IsNullOrWhiteSpace(r.Sni) || r.Sni.Length > 253) return false;
                string sni = r.Sni.Trim().TrimEnd('.');
                bool singleLabel = !sni.Contains('.')
                    && Regex.IsMatch(sni, @"\A[a-zA-Z0-9-]{1,63}\z", RegexOptions.CultureInvariant);
                if (!singleLabel && !TryCanonicalLegacyHost(sni, out sni)) return false;
                var labels = sni.Split('.');
                double entropy = ShannonEntropy(sni);
                double average = labels.Average(label => label.Length);
                bool longName = sni.Length >= 40;
                bool highEntropy = entropy >= 3.7;
                bool manyHyphens = labels.Any(label => label.Count(c => c == '-') >= 3);
                if (!(singleLabel || longName || highEntropy || manyHyphens)) return false;
                string src = IPAddress.Parse(r.Source!).ToString();
                string dst = IPAddress.Parse(r.Destination!).ToString();
                if (SuppressRepeat(now, "R049", src, dst, r.DestinationPort)) return false;
                det = new DetectionEvent
                {
                    RuleId = "R049",
                    Description = $"Unusual TLS SNI shape (length={sni.Length}, entropy={entropy:F2}, average-label={average:F1}, labels={labels.Length})",
                    SourceIp = src, DestinationIp = dst, DestinationPort = r.DestinationPort,
                    Protocol = "TLS", Severity = highEntropy || longName ? SeverityLevel.Medium : SeverityLevel.Low,
                    Count = 1
                };
                return true;
            }
            catch (Exception ex) { Console.Error.WriteLine($"[RuleEngine] R049 error: {ex.GetType().Name}"); }
            return false;
        }
    }
}
