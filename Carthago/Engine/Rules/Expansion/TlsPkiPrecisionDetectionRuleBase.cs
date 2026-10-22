// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/TlsPkiPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class TlsPkiPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);

        private static readonly HashSet<int> SensitiveServicePorts = new() { 3389, 5985, 5986, 445, 389, 636, 1433, 3306, 5432 };
        private static readonly HashSet<int> UncommonH2Ports = new() { 8081, 8444, 9443, 10443, 5001 };

        private static readonly string[] BrowserProcesses =
        {
            "chrome", "msedge", "edge", "firefox", "brave", "opera", "iexplore", "safari"
        };

        private static readonly string[] DynamicDnsSuffixes =
        {
            "duckdns.org", "no-ip.org", "no-ip.com", "dynu.net", "hopto.org", "ddns.net", "myftp.biz", "serveftp.net", "zapto.org", "sytes.net", "serveo.net", "ngrok.io", "ngrok-free.app"
        };

        private static readonly string[] SuspiciousIssuerTokens =
        {
            "unknown", "localhost", "default", "snakeoil", "test ca", "mitmproxy"
        };

        private static readonly string[] HandshakeFailureTokens =
        {
            "handshake failure", "tls alert", "bad certificate", "unknown ca", "certificate unknown", "decrypt error", "protocol version", "handshake_failure"
        };

        private static readonly string[] MalwareLabelTokens =
        {
            "malware ja3", "malware ja4", "cobalt strike ja3", "sliver ja3", "meterpreter ja3", "cobalt strike ja4", "sliver ja4"
        };

        private static readonly Regex CnRegex = new(@"(?i)\bCN\s*=\s*(?<cn>[^,;/]+)", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex WildcardRegex = new(@"^\*\.[A-Za-z0-9.-]+$", RegexOptions.Compiled | RegexOptions.CultureInvariant);

        protected TlsPkiPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected RuleEvaluationResult MatchTls(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string tlsFamily,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null)
        {
            var record = context.Record;
            var host = BestHost(record);
            var items = new List<DetectionEvidenceItem>
            {
                new("tls.family", tlsFamily, "tls-pki"),
                new("tls.host", string.IsNullOrWhiteSpace(host) ? record.Destination ?? "unknown" : host, "tls-pki")
            };

            if (!string.IsNullOrWhiteSpace(record.TlsVersion))
                items.Add(new DetectionEvidenceItem("tls.version", record.TlsVersion!, "tls"));
            if (!string.IsNullOrWhiteSpace(record.Alpn))
                items.Add(new DetectionEvidenceItem("tls.alpn", record.Alpn!, "tls"));
            if (!string.IsNullOrWhiteSpace(record.Ja3))
                items.Add(new DetectionEvidenceItem("tls.ja3", record.Ja3!, "tls"));
            if (!string.IsNullOrWhiteSpace(record.Ja4))
                items.Add(new DetectionEvidenceItem("tls.ja4", record.Ja4!, "tls"));
            if (record.DestinationPort.HasValue)
                items.Add(new DetectionEvidenceItem("network.destinationPort", record.DestinationPort.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "network"));
            if (!string.IsNullOrWhiteSpace(record.ProcessName))
                items.Add(new DetectionEvidenceItem("process.name", record.ProcessName!, "process"));

            if (evidenceItems != null)
                items.AddRange(evidenceItems);

            var evt = CreateDetectionEvent(
                context,
                severity,
                summary,
                items,
                configureConfidence,
                count,
                window.HasValue ? (int)window.Value.TotalSeconds : 0);

            var effectiveCooldownKey = string.IsNullOrWhiteSpace(cooldownKey) ? null : $"{Descriptor.RuleId}:{cooldownKey}";
            var cooldown = PrecisionProfile.Cooldown ?? TimeSpan.Zero;
            if (effectiveCooldownKey != null
                && cooldown > TimeSpan.Zero
                && IsSuppressedByCooldown(effectiveCooldownKey, context.TimestampUtc, cooldown, out var remaining))
            {
                SuppressForCooldown(evt, $"Rule-owned cooldown active for {remaining.TotalSeconds:F0}s.");
                EvidenceBuilder.AppendEvidence(evt, "suppression.remainingSeconds", Math.Ceiling(remaining.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule");
            }

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        protected static IEnumerable<DetectionEvidenceItem> AnalystContext(
            string whyMatched,
            string severityReason,
            string falsePositiveNotes,
            params string[] recommendedActions)
        {
            var items = new List<DetectionEvidenceItem>();
            if (!string.IsNullOrWhiteSpace(whyMatched))
                items.Add(new DetectionEvidenceItem("analyst.whyMatched", whyMatched.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(severityReason))
                items.Add(new DetectionEvidenceItem("analyst.severityReason", severityReason.Trim(), "rule"));
            if (!string.IsNullOrWhiteSpace(falsePositiveNotes))
                items.Add(new DetectionEvidenceItem("analyst.falsePositives", falsePositiveNotes.Trim(), "rule"));

            for (var index = 0; index < recommendedActions.Length; index++)
            {
                if (!string.IsNullOrWhiteSpace(recommendedActions[index]))
                    items.Add(new DetectionEvidenceItem($"response.recommended.{index + 1}", recommendedActions[index].Trim(), "rule"));
            }

            return items;
        }

        protected static string BestHost(TrafficRecord record)
            => NormalizeHost(FirstNonEmpty(record.Sni, record.TlsSni, record.HttpHost, record.DnsQname, record.Destination)) ?? string.Empty;

        protected static string Text(TrafficRecord record)
            => string.Join(" ", new[]
            {
                record.Info,
                record.Protocol,
                record.ApplicationProtocol,
                record.ApplicationService,
                record.HttpHost,
                record.HttpUri,
                record.HttpRequestHeaders,
                record.HttpUserAgent,
                record.Sni,
                record.TlsSni,
                record.Alpn,
                record.TlsVersion,
                record.Ja3,
                record.Ja4,
                record.Ja4S,
                record.Ja4X,
                record.CertIssuer,
                record.CertSubject,
                record.ProcessName,
                record.WhoisASN,
                record.WhoisOrganization
            }.Where(static value => !string.IsNullOrWhiteSpace(value))!);

        protected static bool IsTls(TrafficRecord record)
            => HasAny(record.Sni, record.TlsSni, record.TlsVersion, record.Alpn, record.CertIssuer, record.CertSubject, record.Ja3, record.Ja4, record.Ja4S, record.Ja4X)
               || ContainsAny(record.Protocol, "tls", "https", "ssl")
               || ContainsAny(record.ApplicationProtocol, "tls", "https", "ssl")
               || ContainsAny(record.ApplicationService, "tls", "https", "ssl")
               || record.DestinationPort is 443 or 8443 or 9443 or 5986 or 853;

        protected static bool IsWeakTlsVersion(string? version)
        {
            if (string.IsNullOrWhiteSpace(version))
                return false;

            var normalized = version.Trim().ToLowerInvariant();
            return normalized.Contains("tls 1.0", StringComparison.Ordinal)
                   || normalized.Contains("tls1.0", StringComparison.Ordinal)
                   || normalized.Contains("tls 1.1", StringComparison.Ordinal)
                   || normalized.Contains("tls1.1", StringComparison.Ordinal)
                   || normalized.Contains("ssl3", StringComparison.Ordinal)
                   || normalized.Contains("ssl 3", StringComparison.Ordinal);
        }

        protected static bool IsLikelySelfSigned(TrafficRecord record)
        {
            var issuer = NormalizeNameToken(ExtractCertificateName(record.CertIssuer));
            var subject = NormalizeNameToken(ExtractCertificateName(record.CertSubject));
            return !string.IsNullOrWhiteSpace(issuer)
                   && !string.IsNullOrWhiteSpace(subject)
                   && string.Equals(issuer, subject, StringComparison.OrdinalIgnoreCase);
        }

        protected static bool HasSuspiciousIssuer(TrafficRecord record)
            => !string.IsNullOrWhiteSpace(record.CertIssuer)
               && ContainsAny(record.CertIssuer, SuspiciousIssuerTokens);

        protected static string CertificateSubjectName(TrafficRecord record)
            => NormalizeNameToken(ExtractCertificateName(record.CertSubject)) ?? string.Empty;

        protected static bool IsWildcardSubject(TrafficRecord record)
        {
            var subject = CertificateSubjectName(record);
            return !string.IsNullOrWhiteSpace(subject) && WildcardRegex.IsMatch(subject);
        }

        protected static double CertificateValidityDays(TrafficRecord record)
        {
            if (!record.CertValidFrom.HasValue || !record.CertValidTo.HasValue)
                return 0;

            return (record.CertValidTo.Value - record.CertValidFrom.Value).TotalDays;
        }

        protected static bool IsValidityTooLong(TrafficRecord record)
            => CertificateValidityDays(record) >= 825;

        protected static bool IsShortLivedCertificate(TrafficRecord record)
        {
            var days = CertificateValidityDays(record);
            return days > 0 && days <= 30;
        }

        protected static bool IsIpLiteralName(string? value)
            => !string.IsNullOrWhiteSpace(value) && IPAddress.TryParse(NormalizeHost(value), out _);

        protected static bool HostUsesDynamicDnsProvider(string? host)
        {
            var normalized = NormalizeHost(host) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            foreach (var suffix in DynamicDnsSuffixes)
            {
                if (!normalized.EndsWith("." + suffix, StringComparison.OrdinalIgnoreCase))
                    continue;

                if (string.Equals(normalized, suffix, StringComparison.OrdinalIgnoreCase))
                    return false;

                return true;
            }

            return false;
        }

        protected static bool IsKnownMalwareLabel(TrafficRecord record)
            => HasAny(record.Ja3, record.Ja4, record.Ja4S, record.Ja4X)
               && ContainsAny(Text(record), MalwareLabelTokens);

        protected static bool IsSensitiveTlsService(TrafficRecord record)
            => SensitiveServicePorts.Contains(record.DestinationPort ?? -1);

        protected static bool IsUncommonH2Port(TrafficRecord record)
            => UncommonH2Ports.Contains(record.DestinationPort ?? -1);

        protected static bool HasH2Alpn(TrafficRecord record)
            => ContainsAny(record.Alpn, "h2")
               || ContainsAny(record.QuicAlpn, "h2")
               || ContainsAny(Text(record), "http/2", " h2 ");

        protected static bool HasHandshakeFailure(TrafficRecord record)
            => ContainsAny(Text(record), HandshakeFailureTokens);

        protected static bool IsLikelyBrowserProcess(string? processName)
            => ContainsAny(processName, BrowserProcesses);

        protected static bool SubjectMismatchsSni(TrafficRecord record)
        {
            var sni = NormalizeHost(BestHost(record));
            var subject = CertificateSubjectName(record);
            if (string.IsNullOrWhiteSpace(sni) || string.IsNullOrWhiteSpace(subject))
                return false;

            if (IsIpLiteralName(sni) || IsIpLiteralName(subject))
                return false;

            if (CoversSni(subject, sni))
                return false;

            var sniRoot = RootDomain(sni);
            var subjectRoot = RootDomain(subject.TrimStart('*', '.'));
            if (string.IsNullOrWhiteSpace(sniRoot) || string.IsNullOrWhiteSpace(subjectRoot))
                return false;

            return !string.Equals(sniRoot, subjectRoot, StringComparison.OrdinalIgnoreCase);
        }

        protected static int CountWindowEvents(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(timestamp => now - timestamp > window);
                return list.Count;
            }
        }

        protected static int CountDistinctValues(string key, string value, DateTime now, TimeSpan window)
        {
            var map = DistinctWindows.GetOrAdd(key, _ => new ConcurrentDictionary<string, DateTime>(StringComparer.OrdinalIgnoreCase));
            map[value] = now;
            foreach (var item in map.ToArray())
            {
                if (now - item.Value > window)
                    map.TryRemove(item.Key, out _);
            }

            return map.Count;
        }

        protected static int IntSetting(string ruleId, string key, int defaultValue, int min, int max)
            => RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max);

        protected static RulePrecisionProfile CreateTlsPkiProfile(
            string ruleId,
            RulePrecisionMaturity maturity,
            RuleRuntimeMode defaultMode,
            IReadOnlyCollection<RuleTelemetryKind> requiredTelemetry,
            IReadOnlyCollection<string> requiredFields,
            IReadOnlyCollection<string> evidenceFields,
            IReadOnlyCollection<string> positiveConditions,
            IReadOnlyCollection<string> negativeConditions,
            int minimumConfidence,
            int? threshold,
            TimeSpan? window,
            TimeSpan? cooldown,
            string? distinctBy,
            IReadOnlyCollection<string> falsePositives,
            IReadOnlyCollection<string> tuningKnobs,
            IReadOnlyCollection<string> requiredTests)
        {
            return new RulePrecisionProfile(
                ruleId,
                maturity,
                defaultMode,
                new HashSet<RuleTelemetryKind>(requiredTelemetry),
                new HashSet<string>(requiredFields, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(new[] { "process.name", "whois.asn", "whois.organization" }, StringComparer.OrdinalIgnoreCase),
                new HashSet<string>(evidenceFields, StringComparer.OrdinalIgnoreCase),
                positiveConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                negativeConditions.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                minimumConfidence,
                threshold,
                window,
                cooldown,
                distinctBy,
                falsePositives.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                tuningKnobs.Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                Array.Empty<string>(),
                requiredTests.Distinct(StringComparer.OrdinalIgnoreCase).ToArray());
        }

        protected static string ShortText(string value, int maxLength = 160)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
                return value;

            return value[..maxLength] + "...";
        }

        protected static bool IsInternalAddress(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            var host = ipOrHost.Trim();
            if (!IPAddress.TryParse(host, out var ip))
            {
                var normalized = NormalizeHost(host) ?? string.Empty;
                return normalized.EndsWith(".local", StringComparison.OrdinalIgnoreCase)
                       || normalized.EndsWith(".lan", StringComparison.OrdinalIgnoreCase)
                       || normalized.EndsWith(".internal", StringComparison.OrdinalIgnoreCase)
                       || normalized.EndsWith(".corp", StringComparison.OrdinalIgnoreCase)
                       || normalized.EndsWith(".home", StringComparison.OrdinalIgnoreCase);
            }

            var bytes = ip.GetAddressBytes();
            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return bytes[0] == 10
                       || (bytes[0] == 172 && bytes[1] >= 16 && bytes[1] <= 31)
                       || (bytes[0] == 192 && bytes[1] == 168)
                       || bytes[0] == 127
                       || (bytes[0] == 169 && bytes[1] == 254);
            }

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return ip.IsIPv6LinkLocal
                       || ip.IsIPv6SiteLocal
                       || host.StartsWith("fc", StringComparison.OrdinalIgnoreCase)
                       || host.StartsWith("fd", StringComparison.OrdinalIgnoreCase)
                       || IPAddress.IsLoopback(ip);
            }

            return false;
        }

        protected static bool IsExternalAddress(string? ipOrHost)
            => !string.IsNullOrWhiteSpace(ipOrHost) && !IsMulticastOrBroadcast(ipOrHost) && !IsInternalAddress(ipOrHost);

        protected static bool ContainsAny(string? value, IEnumerable<string> needles)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            foreach (var needle in needles)
            {
                if (!string.IsNullOrWhiteSpace(needle) && value.IndexOf(needle, StringComparison.OrdinalIgnoreCase) >= 0)
                    return true;
            }

            return false;
        }

        protected static bool ContainsAny(string? value, params string[] needles)
            => ContainsAny(value, (IEnumerable<string>)needles);

        private static string ExtractCertificateName(string? name)
        {
            if (string.IsNullOrWhiteSpace(name))
                return string.Empty;

            var match = CnRegex.Match(name);
            return match.Success ? match.Groups["cn"].Value.Trim() : name.Trim();
        }

        private static string? NormalizeNameToken(string? value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return null;

            var trimmed = value.Trim().Trim('"', '\'');
            if (trimmed.StartsWith("CN=", StringComparison.OrdinalIgnoreCase))
                trimmed = ExtractCertificateName(trimmed);

            return NormalizeHost(trimmed) ?? trimmed.ToLowerInvariant();
        }

        private static bool CoversSni(string subject, string sni)
        {
            var normalizedSubject = NormalizeNameToken(subject) ?? string.Empty;
            var normalizedSni = NormalizeHost(sni) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalizedSubject) || string.IsNullOrWhiteSpace(normalizedSni))
                return false;

            if (string.Equals(normalizedSubject, normalizedSni, StringComparison.OrdinalIgnoreCase))
                return true;

            if (!normalizedSubject.StartsWith("*.", StringComparison.Ordinal))
                return false;

            var suffix = normalizedSubject[1..];
            return normalizedSni.EndsWith(suffix, StringComparison.OrdinalIgnoreCase)
                   && normalizedSni.Count(ch => ch == '.') >= suffix.Count(ch => ch == '.');
        }

        private static string RootDomain(string host)
        {
            var normalized = NormalizeHost(host) ?? string.Empty;
            if (string.IsNullOrWhiteSpace(normalized))
                return string.Empty;

            var labels = normalized.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (labels.Length <= 2)
                return normalized;

            var lastTwo = $"{labels[^2]}.{labels[^1]}";
            var lastThree = $"{labels[^3]}.{lastTwo}";
            if (lastTwo is "co.uk" or "org.uk" or "gov.uk" or "com.au" or "co.jp")
                return lastThree;

            return lastTwo;
        }

        private static bool HasAny(params string?[] values)
            => values.Any(static value => !string.IsNullOrWhiteSpace(value));

        private static bool IsMulticastOrBroadcast(string? ipOrHost)
        {
            if (string.IsNullOrWhiteSpace(ipOrHost))
                return false;

            if (!IPAddress.TryParse(ipOrHost.Trim(), out var ip))
                return ContainsAny(ipOrHost, "255.255.255.255");

            if (ip.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                var bytes = ip.GetAddressBytes();
                return (bytes[0] >= 224 && bytes[0] <= 239) || ip.Equals(IPAddress.Broadcast);
            }

            return ip.IsIPv6Multicast;
        }

        private static string? NormalizeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host))
                return null;

            var trimmed = host.Trim().TrimEnd('.').ToLowerInvariant();
            if ((trimmed.StartsWith("http://", StringComparison.OrdinalIgnoreCase) || trimmed.StartsWith("https://", StringComparison.OrdinalIgnoreCase))
                && Uri.TryCreate(trimmed, UriKind.Absolute, out var absolute))
            {
                return absolute.Host.Trim().TrimEnd('.').ToLowerInvariant();
            }

            if (trimmed.Contains('/') && Uri.TryCreate("https://" + trimmed, UriKind.Absolute, out var partial))
                return partial.Host.Trim().TrimEnd('.').ToLowerInvariant();

            if (trimmed.Count(character => character == ':') == 1
                && trimmed.Contains('.')
                && trimmed.LastIndexOf(':') > trimmed.LastIndexOf(']'))
            {
                trimmed = trimmed[..trimmed.LastIndexOf(':')];
            }

            return trimmed;
        }


        public static void ResetSharedStateForReplay()
        {
            TimeWindows.Clear();
            DistinctWindows.Clear();
            CooldownWindows.Clear();
        }

        private static bool IsSuppressedByCooldown(string key, DateTime now, TimeSpan cooldown, out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;
            if (CooldownWindows.TryGetValue(key, out var previous) && now - previous < cooldown)
            {
                remaining = cooldown - (now - previous);
                return true;
            }

            CooldownWindows[key] = now;
            return false;
        }
    }
}
