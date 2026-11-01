// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R549_CrossSubnetDefaultBasicCredentialFanoutRule.cs
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Net;
using System.Net.Sockets;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>
    /// Correlates wire-classified default HTTP Basic credential attempts
    /// from one RFC1918 source to admin routes in three different private /24s.
    /// An attempt is not an authenticated login or a compromised device.
    /// </summary>
    public sealed class R549_CrossSubnetDefaultBasicCredentialFanoutRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan ObservationWindow = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);

        private static readonly RuleDescriptor Rule = new(
            RuleId: "R549",
            Name: "Cross-Subnet Default Basic Credential Fanout",
            Category: "IdentityAccess",
            Description: "A private IPv4 source sends parser-confirmed default Basic Authorization to admin routes in three distinct private /24 networks within five minutes; authentication outcomes are unknown.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R549.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R549",
            maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "protocol_or_port" },
            evidenceFields: new[] { "http.defaultBasicObserved", "matched_conditions", "count", "window_seconds" },
            positiveConditions: new[]
            {
                "A complete cleartext HTTP/1.x request must have exactly one parser-confirmed known-default Basic Authorization value; no raw credentials are retained.",
                "The request must target an anchored administrative route, with coherent TCP, HTTP, IPv4 and bounded payload metadata.",
                "One RFC1918 source must address three distinct RFC1918 /24 destination networks, excluding its own /24, within five minutes."
            },
            negativeConditions: new[]
            {
                "Reject generic Basic, unknown credentials, missing or duplicated Authorization, incomplete headers, port-only or Info-only claims.",
                "Reject TLS/HTTPS, HTTP/2 or HTTP/3 ciphertext, non-admin routes, same-subnet provisioning, one-target retries, contradictory metadata and out-of-order timestamps.",
                "Do not infer credential acceptance, host identity, device role, authorization, a server response or exploitation."
            },
            minimumConfidence: 88,
            threshold: 3,
            window: ObservationWindow,
            cooldown: Cooldown,
            distinctBy: "private_source+distinct_private_destination_24",
            falsePositives: new[]
            {
                "Approved cross-VLAN device provisioning, factory-reset recovery, vulnerability scans and legacy inventory can test known default credentials.",
                "NAT, VPN routing and capture vantage point can obscure the true operator or endpoint identity."
            },
            tuningKnobs: new[] { "Mode", "ApprovedProvisioningHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "real HTTP parser and PacketHandler positive classification",
                "non-default Basic, duplicate or incomplete header, benign same-subnet and ordinary browsing negatives",
                "forged Info, imported JSON, contradictory transport, encrypted and malformed evidence fail-closed",
                "distinct /24, packet-ID deduplication, out-of-order, window expiry, cooldown and concurrency",
                "privacy, Shadow/Candidate policy, confidence floor and registry uniqueness"
            });

        private readonly NetworkBatch226230Evidence.Window _observations = new();
        private readonly object _cooldownGate = new();
        private readonly Dictionary<string, DateTime> _lastEmission = new(StringComparer.Ordinal);

        public R549_CrossSubnetDefaultBasicCredentialFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (record.Id == Guid.Empty
                || !record.HttpBasicDefaultCredentialObserved
                || !record.IsTcp || record.IsUdp || record.IsQuic
                || record.IpVersion != 4
                || !string.Equals(record.Protocol, "TCP", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(record.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || record.TlsVersion != null || record.Sni != null || record.Alpn != null
                || record.DnsQname != null || record.DnsAnswers != null || record.DnsQtype != null
                || record.HttpMethod is not ("GET" or "POST")
                || record.SourcePort is null or < 1024 or > 65535
                || record.DestinationPort is not (80 or 8080 or 8000 or 8008 or 8888)
                || record.L4Len is null or < 40 or > 4096
                || !IsAdminPath(record.HttpUri)
                || !SafeHost(record.HttpHost)
                || record.HttpRequestHeaders?.Contains("Authorization: [REDACTED]", StringComparison.OrdinalIgnoreCase) != true
                || !TryPrivate24(record.Source, out var sourceSubnet)
                || !TryPrivate24(record.Destination, out var destinationSubnet)
                || string.Equals(sourceSubnet, destinationSubnet, StringComparison.Ordinal))
                return NoMatch();

            var key = record.Source!;
            var count = _observations.Observe(key, destinationSubnet, record.Id,
                context.TimestampUtc, ObservationWindow, distinctTargets: true);
            if (count != 3)
                return NoMatch();

            lock (_cooldownGate)
            {
                if (_lastEmission.TryGetValue(key, out var previous)
                    && context.TimestampUtc >= previous
                    && context.TimestampUtc - previous < Cooldown)
                    return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

                if (_lastEmission.Count >= 4096 && !_lastEmission.ContainsKey(key))
                {
                    var expired = new List<string>();
                    foreach (var entry in _lastEmission)
                        if (context.TimestampUtc - entry.Value >= Cooldown)
                            expired.Add(entry.Key);
                    foreach (var expiredKey in expired)
                        _lastEmission.Remove(expiredKey);
                    if (_lastEmission.Count >= 4096)
                        return NoMatch();
                }
                _lastEmission[key] = context.TimestampUtc;
            }

            // Never copy Authorization, HttpUri, HttpRequestHeaders, Info, or
            // credentials into evidence. Only the parser-derived boolean and
            // bounded correlation summary are necessary for this predicate.
            var evidence = new[]
            {
                new DetectionEvidenceItem("http.defaultBasicObserved", "true", "bounded-http-parser"),
                new DetectionEvidenceItem("matched_conditions", "parsed_default_basic,admin_route,three_private_destination_subnets", "rule"),
                new DetectionEvidenceItem("count", count.ToString(CultureInfo.InvariantCulture), "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Default HTTP Basic credential attempts across three private subnets (outcomes unverified)",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.46, "parser-confirmed-default-basic");
                    confidence.AddEvidence(0.28, "cleartext-admin-request");
                    confidence.AddCorrelation(0.20, "three-distinct-private-subnets");
                }, count: count, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool TryPrivate24(string? address, out string subnet)
        {
            subnet = string.Empty;
            if (!IPAddress.TryParse(address, out var ip)
                || ip.AddressFamily != AddressFamily.InterNetwork)
                return false;
            var b = ip.GetAddressBytes();
            if (!(b[0] == 10
                || b[0] == 172 && b[1] is >= 16 and <= 31
                || b[0] == 192 && b[1] == 168))
                return false;
            subnet = string.Concat(b[0].ToString(CultureInfo.InvariantCulture), ".",
                b[1].ToString(CultureInfo.InvariantCulture), ".",
                b[2].ToString(CultureInfo.InvariantCulture));
            return true;
        }

        private static bool IsAdminPath(string? uri)
        {
            if (string.IsNullOrEmpty(uri) || uri.Length > 256 || uri[0] != '/')
                return false;
            var queryStart = uri.IndexOf('?');
            var path = queryStart < 0 ? uri : uri[..queryStart];
            return path.Equals("/admin", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/admin/", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/login.cgi", StringComparison.OrdinalIgnoreCase)
                || path.Equals("/setup.cgi", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/cgi-bin/luci/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/goform/", StringComparison.OrdinalIgnoreCase)
                || path.StartsWith("/boaform/", StringComparison.OrdinalIgnoreCase);
        }

        private static bool SafeHost(string? host)
        {
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253)
                return false;
            foreach (var ch in host)
                if (char.IsWhiteSpace(ch) || ch is '@' or '/' or '?' or '#' or '\\')
                    return false;
            return true;
        }
    }
}
