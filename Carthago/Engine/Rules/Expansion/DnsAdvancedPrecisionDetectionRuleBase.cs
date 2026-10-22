// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/DnsAdvancedPrecisionDetectionRuleBase.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Engine.Rules.Dns;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public abstract class DnsAdvancedPrecisionDetectionRuleBase : DnsPrecisionDetectionRuleBase
    {
        private static readonly string[] MiningPoolRoots =
        {
            "2miners.com", "ethermine.org", "minexmr.com", "monerohash.com", "nanopool.org", "nicehash.com", "supportxmr.com", "xmrpool.net"
        };

        private static readonly string[] TorGatewayRoots =
        {
            "onion.to", "onion.city", "tor2web.io", "tor2web.org", "tor2web.fi", "onion.sh"
        };

        private static readonly string[] HighRiskTlds =
        {
            "zip", "mov", "top", "xyz", "click", "country", "gq", "tk"
        };

        private static readonly string[] CanaryOrMetadataRoots =
        {
            "burpcollaborator.net", "canarytokens.com", "interact.sh", "oastify.com", "requestbin.net", "metadata.google.internal", "instance-data.ec2.internal"
        };

        private static readonly string[] AdSrvPrefixes =
        {
            "_ldap._tcp", "_kerberos._tcp", "_gc._tcp", "_kpasswd._tcp"
        };

        private static readonly string[] CommonAsciiHomographTlds =
        {
            "app", "biz", "cloud", "com", "dev", "info", "io", "net", "online", "org"
        };

        private static readonly string[] BrowserProcesses =
        {
            "chrome", "msedge", "edge", "firefox", "brave", "opera", "iexplore", "safari"
        };

        private static readonly Dictionary<string, string[]> BrandLookalikes = new(StringComparer.OrdinalIgnoreCase)
        {
            ["microsoft"] = new[] { "micros0ft", "rnicrosoft" },
            ["google"] = new[] { "g00gle" },
            ["amazon"] = new[] { "amaz0n" },
            ["cloudflare"] = new[] { "cloudfiare", "cloudfl4re" },
            ["paypal"] = new[] { "paypai" },
            ["apple"] = new[] { "appie", "app1e" }
        };

        protected DnsAdvancedPrecisionDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
            : base(descriptor, precisionProfile)
        {
        }

        protected static bool IsMiningPoolQuery(string query)
            => MatchesRootOrSubdomain(query, MiningPoolRoots);

        protected static bool HasExplicitMiningPoolSignal(string query)
            => ContainsAny(LeftOfRoot(query), "pool", "stratum", "rig", "solo", "xmr", "eth", "btc", "mine")
               || ContainsAny(SecondLevelLabel(query), "xmr", "pool", "mine");

        protected static bool IsTorGatewayQuery(string query)
            => MatchesRootOrSubdomain(query, TorGatewayRoots)
               || query.Contains(".onion.", StringComparison.OrdinalIgnoreCase)
               || query.EndsWith(".onion", StringComparison.OrdinalIgnoreCase);

        protected static bool IsHighRiskTldQuery(string query)
            => HighRiskTlds.Contains(TopLevelDomain(query), StringComparer.OrdinalIgnoreCase);

        protected static bool IsDnssecQueryType(string? qtype)
            => string.Equals(qtype, "DNSKEY", StringComparison.OrdinalIgnoreCase)
               || string.Equals(qtype, "DS", StringComparison.OrdinalIgnoreCase)
               || string.Equals(qtype, "RRSIG", StringComparison.OrdinalIgnoreCase)
               || string.Equals(qtype, "NSEC", StringComparison.OrdinalIgnoreCase)
               || string.Equals(qtype, "NSEC3", StringComparison.OrdinalIgnoreCase);

        protected static bool IsReverseLookupQuery(string query)
            => query.EndsWith(".in-addr.arpa", StringComparison.OrdinalIgnoreCase)
               || query.EndsWith(".ip6.arpa", StringComparison.OrdinalIgnoreCase);

        protected static bool IsCanaryOrMetadataQuery(string query)
            => MatchesRootOrSubdomain(query, CanaryOrMetadataRoots);

        protected static bool IsAdSrvQuery(string query)
        {
            foreach (var prefix in AdSrvPrefixes)
            {
                if (query.StartsWith(prefix + ".", StringComparison.OrdinalIgnoreCase))
                    return true;
            }

            return false;
        }

        protected static bool IsNxDomain(TrafficRecord record)
            => string.Equals(record.DnsRcode, "NXDOMAIN", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.DnsRcode, "3", StringComparison.OrdinalIgnoreCase)
               || string.Equals(record.DnsRcode, "Name Error", StringComparison.OrdinalIgnoreCase);

        protected static bool LooksConsonantHeavyDga(string query, double entropyThreshold, double vowelRatioThreshold, int minimumLength)
        {
            var secondLevel = SecondLevelLabel(query);
            if (string.IsNullOrWhiteSpace(secondLevel) || secondLevel.Length < minimumLength || LooksLikePunycodeLabel(secondLevel))
                return false;

            var letters = secondLevel.Where(char.IsLetter).Select(char.ToLowerInvariant).ToArray();
            if (letters.Length < minimumLength)
                return false;

            var vowelRatio = VowelRatio(secondLevel);
            var entropy = ShannonEntropy(secondLevel);
            var consonantRatio = letters.Count(character => "bcdfghjklmnpqrstvwxyz".Contains(character)) / (double)letters.Length;
            return entropy >= entropyThreshold
                   && vowelRatio <= vowelRatioThreshold
                   && consonantRatio >= 0.75;
        }

        protected static bool TryGetPunycodeHomographLabel(string query, out string label)
        {
            label = string.Empty;
            var parts = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            if (parts.Length < 2)
                return false;

            var tld = parts[^1];
            if (!CommonAsciiHomographTlds.Contains(tld, StringComparer.OrdinalIgnoreCase))
                return false;

            foreach (var part in parts.Take(parts.Length - 1))
            {
                if (LooksLikePunycodeLabel(part) && !LooksLikeInternalOnlyDnsName(query))
                {
                    label = part;
                    return true;
                }
            }

            return false;
        }

        protected static bool TryGetCloudBrandLookalike(string query, out string brand, out string matchedLabel)
        {
            brand = string.Empty;
            matchedLabel = string.Empty;
            var labels = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            foreach (var label in labels)
            {
                var normalized = label.Trim().ToLowerInvariant();
                foreach (var pair in BrandLookalikes)
                {
                    if (pair.Value.Any(candidate => string.Equals(candidate, normalized, StringComparison.OrdinalIgnoreCase)))
                    {
                        brand = pair.Key;
                        matchedLabel = normalized;
                        return true;
                    }
                }
            }

            return false;
        }

        protected static bool TryGetPrivateAnswerIp(string? answers, out string privateIp, out bool loopbackOrLinkLocal, out bool mixedPublicAndPrivate)
        {
            privateIp = string.Empty;
            loopbackOrLinkLocal = false;
            mixedPublicAndPrivate = false;
            var parsed = ParseAnswerIps(answers).ToArray();
            if (parsed.Length == 0)
                return false;

            var privateAnswers = parsed.Where(IsPrivateOrReserved).ToArray();
            if (privateAnswers.Length == 0)
                return false;

            privateIp = privateAnswers[0].ToString();
            loopbackOrLinkLocal = privateAnswers.Any(static ip => IPAddress.IsLoopback(ip) || ip.IsIPv6LinkLocal);
            mixedPublicAndPrivate = privateAnswers.Length < parsed.Length;
            return true;
        }

        protected static bool LooksLikeBrowserProcess(string? processName)
            => ContainsAny(processName, BrowserProcesses);

        protected static bool IsExternalEndpoint(string? address)
            => !string.IsNullOrWhiteSpace(address) && IPAddress.TryParse(address, out var parsed) && !IsPrivateOrReserved(parsed);

        protected static bool IsInternalEndpoint(string? address)
            => !string.IsNullOrWhiteSpace(address) && IPAddress.TryParse(address, out var parsed) && IsPrivateOrReserved(parsed);

        protected static string TopLevelDomain(string query)
        {
            var parts = query.Split('.', StringSplitOptions.RemoveEmptyEntries);
            return parts.Length == 0 ? string.Empty : parts[^1];
        }

        protected static IEnumerable<IPAddress> ParseAnswerIps(string? answers)
        {
            if (string.IsNullOrWhiteSpace(answers))
                yield break;

            foreach (var token in answers.Split(new[] { ' ', ',', ';', '\r', '\n', '\t', '[', ']', '(', ')' }, StringSplitOptions.RemoveEmptyEntries))
            {
                var trimmed = token.Trim().TrimEnd('.');
                if (IPAddress.TryParse(trimmed, out var address))
                    yield return address;
            }
        }

        protected static bool MatchesRootOrSubdomain(string query, IEnumerable<string> roots)
        {
            var normalized = NormalizeDomain(query);
            if (string.IsNullOrWhiteSpace(normalized))
                return false;

            foreach (var root in roots)
            {
                var normalizedRoot = NormalizeDomain(root);
                if (string.IsNullOrWhiteSpace(normalizedRoot))
                    continue;

                if (string.Equals(normalized, normalizedRoot, StringComparison.OrdinalIgnoreCase)
                    || normalized.EndsWith("." + normalizedRoot, StringComparison.OrdinalIgnoreCase))
                {
                    return true;
                }
            }

            return false;
        }

        protected static bool ContainsAny(string? value, params string[] needles)
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
    }
}
