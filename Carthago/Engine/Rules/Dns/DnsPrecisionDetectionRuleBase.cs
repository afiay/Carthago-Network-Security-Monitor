// SPDX-License-Identifier: MIT
// File: Engine/Rules/Dns/DnsPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Text.RegularExpressions;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Baseline;

namespace Carthago.Engine.Rules.Dns
{
    public abstract class DnsPrecisionDetectionRuleBase : PrecisionTelemetryDetectionRuleBase
    {
        private static readonly ConcurrentDictionary<string, DateTime> SeenDomains = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, List<DateTime>> TimeWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, ConcurrentDictionary<string, DateTime>> DistinctWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly ConcurrentDictionary<string, DateTime> CooldownWindows = new(StringComparer.OrdinalIgnoreCase);
        private static readonly string[] DynamicDnsProviders =
        {
            "duckdns.org", "no-ip.org", "noip.com", "ddns.net", "dynu.net", "hopto.org",
            "myqnapcloud.com", "synology.me", "tplinkdns.com", "dyndns.org", "afraid.org", "serveo.net"
        };
        private static readonly string[] BenignValidationPrefixes =
        {
            "_acme-challenge", "_dmarc", "_domainkey", "_mta-sts", "_smtp", "_sip", "_ldap", "_kerberos",
            "autodiscover", "selector1", "selector2"
        };
        private static readonly string[] KnownTelemetryRoots =
        {
            "windowsupdate.com", "microsoft.com", "msftconnecttest.com", "office.com", "apple.com",
            "icloud.com", "google.com", "googleapis.com", "gstatic.com", "amazonaws.com",
            "cloudfront.net", "akadns.net", "akamaiedge.net", "okta.com", "crowdstrike.com",
            "symantec.com", "sentinelone.net", "zoom.us"
        };
        private static readonly string[] CommonTwoLabelPublicSuffixes =
        {
            "ac.uk", "co.uk", "gov.uk", "org.uk",
            "co.jp", "com.au", "net.au", "org.au",
            "com.br", "com.cn", "com.mx", "com.sg",
            "co.in", "co.nz"
        };
        private static readonly string[] InternalDnsSuffixes =
        {
            ".local", ".lan", ".home", ".internal", ".corp", ".intranet"
        };
        private static readonly string[] BenignSingleLabelFallbackNames =
        {
            "autodiscover", "isatap", "wpad"
        };
        private static readonly Regex Ipv4Regex = new(@"\b(?:\d{1,3}\.){3}\d{1,3}\b", RegexOptions.Compiled | RegexOptions.CultureInvariant);
        private static readonly Regex CnameRegex = new(@"\bCNAME\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);
        private static readonly Regex DomainLikeTokenRegex = new(@"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b", RegexOptions.Compiled | RegexOptions.IgnoreCase | RegexOptions.CultureInvariant);

        protected DnsPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        internal static void ResetSharedStateForReplay()
        {
            SeenDomains.Clear();
            TimeWindows.Clear();
            DistinctWindows.Clear();
            CooldownWindows.Clear();
        }

        protected RuleEvaluationResult NoMatch()
            => RuleEvaluationResult.NoMatch(Descriptor.RuleId);

        protected bool TryGetDnsQuestion(RuleEvaluationContext context, out string query)
        {
            query = string.Empty;
            var record = context.Record;
            if (!LooksLikeDns(record) || string.IsNullOrWhiteSpace(record.DnsQname))
                return false;

            var normalized = NormalizeDomain(record.DnsQname);
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            query = normalized;
            return true;
        }

        // Fixed-category DNS evidence for candidate rules that may expose internal names,
        // host labels, identifiers or proprietary zones. Do not serialize raw answers.
        private static bool IsSensitiveDnsRule(string ruleId)
            => string.CompareOrdinal(ruleId, "R178") >= 0 && string.CompareOrdinal(ruleId, "R195") <= 0;

        protected RuleEvaluationResult MatchDns(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            string query,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder> configureConfidence,
            int count = 1,
            TimeSpan? window = null,
            string? cooldownKey = null)
        {
            var items = new List<DetectionEvidenceItem>
            {
                new("dns.qname", IsSensitiveDnsRule(Descriptor.RuleId) ? "[REDACTED]" : query, "dns"),
                new("dns.rootDomain", IsSensitiveDnsRule(Descriptor.RuleId) ? "[REDACTED]" : RootDomain(query), "dns")
            };

            if (!string.IsNullOrWhiteSpace(context.Record.DnsQtype))
                items.Add(new DetectionEvidenceItem("dns.qtype", context.Record.DnsQtype!, "dns"));
            if (!string.IsNullOrWhiteSpace(context.Record.DnsRcode))
                items.Add(new DetectionEvidenceItem("dns.rcode", context.Record.DnsRcode!, "dns"));
            if (context.Record.DnsTtl.HasValue)
                items.Add(new DetectionEvidenceItem("dns.ttl", context.Record.DnsTtl.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "dns"));
            if (!string.IsNullOrWhiteSpace(context.Record.DnsAnswers) && !IsSensitiveDnsRule(Descriptor.RuleId))
                items.Add(new DetectionEvidenceItem("dns.answers", ShortText(context.Record.DnsAnswers!, 240), "dns"));

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
            if (effectiveCooldownKey != null && cooldown > TimeSpan.Zero && IsSuppressedByCooldown(effectiveCooldownKey, context.TimestampUtc, cooldown, out var remaining))
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

        protected static BaselineDecision ObserveBaseline(string kind, string subject, string value, RuleEvaluationContext context, string evidence)
        {
            try
            {
                return BaselineStore.Current.ObserveAsync(new BaselineObservation(kind, subject, value, context.TimestampUtc, evidence)).GetAwaiter().GetResult();
            }
            catch
            {
                return new BaselineDecision(false, true, false, "baseline unavailable", 0, null, null);
            }
        }

        protected static bool LooksLikeDns(TrafficRecord record)
            => string.Equals(record.Protocol, "DNS", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.ApplicationService, "DNS", StringComparison.OrdinalIgnoreCase)
               || !string.IsNullOrWhiteSpace(record.DnsQname)
               || !string.IsNullOrWhiteSpace(record.DnsQtype)
               || !string.IsNullOrWhiteSpace(record.DnsAnswers)
               || !string.IsNullOrWhiteSpace(record.DnsRcode);

        protected static bool IsKnownTelemetryRoot(string rootDomain)
            => HasExactDnsRootMatch(rootDomain, KnownTelemetryRoots);

        protected static bool IsDynamicDnsProvider(string query)
            => HasExactDnsRootMatch(RootDomain(query), DynamicDnsProviders);

        protected static bool AnswerSetContainsKnownTelemetryRoot(string? answers)
        {
            if (string.IsNullOrWhiteSpace(answers))
                return false;

            foreach (Match match in DomainLikeTokenRegex.Matches(answers))
            {
                if (IsKnownTelemetryRoot(RootDomain(match.Value)))
                    return true;
            }

            return false;
        }

        protected static bool LooksLikeBenignValidationQuery(string query)
        {
            var lower = query.ToLowerInvariant();
            return BenignValidationPrefixes.Any(prefix => lower.StartsWith(prefix, StringComparison.OrdinalIgnoreCase));
        }

        protected static bool LooksLikeInternalOnlyDnsName(string query)
            => !query.Contains('.')
               || InternalDnsSuffixes.Any(suffix => query.EndsWith(suffix, StringComparison.OrdinalIgnoreCase));

        protected static bool IsCommonSingleLabelFallbackName(string query)
            => !query.Contains('.')
               && BenignSingleLabelFallbackNames.Any(name => string.Equals(query, name, StringComparison.OrdinalIgnoreCase));

        protected static bool IsTxtLikeDnsQueryType(string? queryType)
            => string.Equals(queryType, "TXT", StringComparison.OrdinalIgnoreCase)
               || string.Equals(queryType, "NULL", StringComparison.OrdinalIgnoreCase);

        protected static bool LooksLikePunycodeLabel(string label)
            => label.StartsWith("xn--", StringComparison.OrdinalIgnoreCase);

        protected static string NormalizeDomain(string? query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return string.Empty;

            var trimmed = query.Trim().TrimEnd('.').ToLowerInvariant();
            return IPAddress.TryParse(trimmed, out _) ? string.Empty : trimmed;
        }

        protected static string RootDomain(string query)
        {
            if (string.IsNullOrWhiteSpace(query))
                return string.Empty;

            var parts = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length <= 2)
                return query;

            var rootLabelCount = GetRootLabelCount(parts);
            return string.Join(".", parts.Skip(parts.Length - rootLabelCount));
        }

        protected static string SecondLevelLabel(string query)
        {
            var parts = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                return string.Empty;

            var rootLabelCount = GetRootLabelCount(parts);
            return parts.Length >= rootLabelCount ? parts[^rootLabelCount] : query;
        }

        protected static string LeftOfRoot(string query)
        {
            var parts = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length == 0)
                return string.Empty;

            var rootLabelCount = GetRootLabelCount(parts);
            return parts.Length <= rootLabelCount
                ? string.Empty
                : string.Join(".", parts.Take(parts.Length - rootLabelCount));
        }

        protected static double ShannonEntropy(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0.0;

            var probabilities = value.GroupBy(static character => character)
                .Select(group => (double)group.Count() / value.Length);
            return -probabilities.Sum(static probability => probability * Math.Log(probability, 2));
        }

        protected static double VowelRatio(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0.0;

            var letters = value.Where(char.IsLetter).ToArray();
            if (letters.Length == 0)
                return 0.0;

            return letters.Count(static character => "aeiou".Contains(char.ToLowerInvariant(character))) / (double)letters.Length;
        }

        protected static double DigitRatio(string value)
        {
            if (string.IsNullOrWhiteSpace(value))
                return 0.0;

            return value.Count(char.IsDigit) / (double)value.Length;
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

        protected static IReadOnlyList<DateTime> SnapshotWindowEvents(string key, DateTime now, TimeSpan window)
        {
            var list = TimeWindows.GetOrAdd(key, _ => new List<DateTime>());
            lock (list)
            {
                list.Add(now);
                list.RemoveAll(timestamp => now - timestamp > window);
                return list.OrderBy(static timestamp => timestamp).ToArray();
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

        protected static bool FirstTimeSeen(string query, DateTime now)
            => SeenDomains.TryAdd(query, now);

        protected static int CountAnswerIps(string? answers)
            => string.IsNullOrWhiteSpace(answers)
                ? 0
                : Ipv4Regex.Matches(answers).Select(match => match.Value).Distinct(StringComparer.OrdinalIgnoreCase).Count();

        protected static int CountCnames(string? answers)
            => string.IsNullOrWhiteSpace(answers) ? 0 : CnameRegex.Matches(answers).Count;

        protected static bool IsExternalDestination(string? destination)
        {
            if (string.IsNullOrWhiteSpace(destination))
                return false;

            if (!IPAddress.TryParse(destination, out var address))
                return !ContainsAny(destination, ".local", ".internal", ".lan", ".corp", ".home");

            return !IsPrivateOrReserved(address);
        }

        protected static bool IsPrivateOrReserved(IPAddress address)
        {
            if (IPAddress.IsLoopback(address))
                return true;

            var bytes = address.GetAddressBytes();
            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetwork)
            {
                return bytes[0] switch
                {
                    10 => true,
                    127 => true,
                    169 when bytes[1] == 254 => true,
                    172 when bytes[1] >= 16 && bytes[1] <= 31 => true,
                    192 when bytes[1] == 168 => true,
                    _ => false
                };
            }

            if (address.AddressFamily == System.Net.Sockets.AddressFamily.InterNetworkV6)
            {
                return address.IsIPv6LinkLocal
                       || address.IsIPv6Multicast
                       || address.IsIPv6SiteLocal
                       || address.Equals(IPAddress.IPv6Loopback);
            }

            return true;
        }

        protected static string ShortText(string value, int maxLength = 160)
        {
            if (string.IsNullOrWhiteSpace(value) || value.Length <= maxLength)
                return value;

            return value[..maxLength] + "...";
        }

        protected static int IntSetting(string ruleId, string key, int defaultValue, int min, int max)
            => RuleEngine.GetRuleIntSetting(ruleId, key, defaultValue, min, max);

        protected static double DoubleSetting(string ruleId, string key, double defaultValue, double min, double max)
            => RuleEngine.GetRuleDoubleSetting(ruleId, key, defaultValue, min, max);

        protected static RulePrecisionProfile CreateDnsProfile(
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
                new HashSet<string>(new[] { "reputation.score", "reputation.lastSeen", "whois.registrar", "whois.organization", "process.name" }, StringComparer.OrdinalIgnoreCase),
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

        private static bool ContainsAny(string? value, params string[] needles)
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

        private static int GetRootLabelCount(string[] parts)
        {
            if (parts.Length <= 2)
                return parts.Length;

            var publicSuffix = parts[^2] + "." + parts[^1];
            return parts.Length >= 3 && CommonTwoLabelPublicSuffixes.Any(suffix => string.Equals(publicSuffix, suffix, StringComparison.OrdinalIgnoreCase))
                ? 3
                : 2;
        }

        private static bool HasExactDnsRootMatch(string? value, params string[] roots)
        {
            if (string.IsNullOrWhiteSpace(value))
                return false;

            var normalized = NormalizeDomain(value);
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            foreach (var root in roots)
            {
                var normalizedRoot = NormalizeDomain(root);
                if (!string.IsNullOrWhiteSpace(normalizedRoot) && string.Equals(normalized, normalizedRoot, StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
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
