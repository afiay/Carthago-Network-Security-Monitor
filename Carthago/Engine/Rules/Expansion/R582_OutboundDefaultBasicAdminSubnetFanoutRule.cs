// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; tests authored, zero executed.
using System;
using Carthago.Models;
using Carthago.Services.EnvironmentTuning;

namespace Carthago.Engine.Rules.Expansion
{
    /// <summary>Known-default HTTP Basic admin requests sent to three public /24s.</summary>
    public sealed class R582_OutboundDefaultBasicAdminSubnetFanoutRule
        : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly TimeSpan Window = TimeSpan.FromMinutes(5);
        private static readonly TimeSpan Cooldown = TimeSpan.FromMinutes(10);
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R582", Name: "Outbound Default HTTP Basic Admin Credential Fanout",
            Category: "IdentityAccess",
            Description: "One private source sends parser-confirmed known-default Basic credentials to admin routes at three public destination /24 networks in five minutes.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R582.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R582", maturity: RulePrecisionMaturity.Candidate,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "protocol_or_port" },
            evidenceFields: new[] { "http.defaultBasicObserved", "matched_conditions", "count", "window_seconds", "http.outcome" },
            positiveConditions: new[]
            {
                "PacketHandler identifies one complete plaintext HTTP/1.x known-default Basic Authorization to an anchored admin route.",
                "One RFC1918 source targets three different globally routable public /24 networks in five minutes.",
                "Require valid TCP/HTTP metadata, redacted Authorization, unique packet IDs and bounded monotonic state."
            },
            negativeConditions: new[]
            {
                "Reject ordinary Basic values, duplicated/partial Authorization, generic browsing and non-admin paths.",
                "Reject private or reserved destinations, one /24, wrong ports, TLS, forged Info, conflicting DNS and Redis evidence.",
                "Do not infer successful authentication, account existence, credential acceptance or remote device identity."
            },
            minimumConfidence: 88, threshold: 3, window: Window, cooldown: Cooldown,
            distinctBy: "private_client+distinct_public_admin_destination_24",
            falsePositives: new[]
            {
                "Approved internet appliance management, disaster recovery and authorized testing may use known defaults.",
                "NAT, proxies and incomplete HTTPS visibility can hide true service identity."
            },
            tuningKnobs: new[] { "Mode", "ApprovedAdminHosts", "ApprovedMaintenanceWindows" },
            requiredTests: new[]
            {
                "actual HTTP parser default Basic classification", "unknown Basic and non-admin negatives",
                "three public /24s, duplicates and mixed sources",
                "special IPs, contradictory metadata, expiry and cooldown",
                "no credential evidence, Candidate Shadow and unique registry ID"
            });
        private readonly CrossBoundaryRequestFanoutWindow _window = new();

        public R582_OutboundDefaultBasicAdminSubnetFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!CrossBoundaryRequestEvidence.Tcp(r, 40, 4096)
                || !r.HttpBasicDefaultCredentialObserved
                || !CrossBoundaryRequestEvidence.NoRedisParserFlags(r)
                || !string.Equals(r.ApplicationProtocol, "HTTP", StringComparison.OrdinalIgnoreCase)
                || r.HttpMethod is not ("GET" or "POST")
                || r.DestinationPort is not (80 or 8080 or 8000 or 8008 or 8888)
                || !IsAdminPath(r.HttpUri) || !SafeHost(r.HttpHost)
                || r.HttpRequestHeaders?.Contains("Authorization: [REDACTED]",
                    StringComparison.OrdinalIgnoreCase) != true
                || !CrossBoundaryRequestEvidence.TryPair(r, publicToPrivate: false,
                    out var client, out var target24))
                return NoMatch();
            var approvals = ApprovedAssetRegistry.Current;
            if (approvals.HasApprovedAdminHosts && approvals.IsAdminHost(client))
                return NoMatch();
            var observation = _window.Observe(client, target24, r.Id, context.TimestampUtc);
            if (observation == FanoutObservation.None) return NoMatch();
            if (observation == FanoutObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("http.defaultBasicObserved", "true", "packet-handler-http-parser"),
                new DetectionEvidenceItem("matched_conditions", "default_basic_admin,three_distinct_public_24s", "rule"),
                new DetectionEvidenceItem("count", "3", "rule"),
                new DetectionEvidenceItem("window_seconds", "300", "rule"),
                new DetectionEvidenceItem("http.outcome", "request_only_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.High,
                "Outbound default Basic admin credential request fanout (authentication unknown)",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.46, "packet-handler-default-basic");
                    confidence.AddEvidence(0.28, "anchored-cleartext-admin-route");
                    confidence.AddCorrelation(0.20, "three-distinct-public-24s");
                }, count: 3, windowSeconds: 300);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        private static bool IsAdminPath(string? uri)
        {
            if (string.IsNullOrEmpty(uri) || uri.Length > 256 || uri[0] != '/')
                return false;
            var q = uri.IndexOf('?');
            var path = q < 0 ? uri : uri.Substring(0, q);
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
            if (string.IsNullOrWhiteSpace(host) || host.Length > 253) return false;
            foreach (var ch in host)
                if (char.IsWhiteSpace(ch) || ch is '@' or '/' or '?' or '#' or '\\')
                    return false;
            return true;
        }
    }
}
