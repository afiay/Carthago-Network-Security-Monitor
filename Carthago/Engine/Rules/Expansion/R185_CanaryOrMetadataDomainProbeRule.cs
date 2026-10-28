// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R185_CanaryOrMetadataDomainProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R185_CanaryOrMetadataDomainProbeRule : DnsAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R185",
            Name: "Canary Or Metadata Domain Probe",
            Category: "DnsAdvanced",
            Description: "Detects structured DNS queries to out-of-band canary or cloud metadata domains instead of generic collaborator text matches.",
            DefaultSeverity: SeverityLevel.Low,
            ConfigKey: "Rules.R185.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateDnsProfile(
            ruleId: "R185",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Dns },
            requiredFields: new[] { "source", "dns_qname" },
            evidenceFields: new[] { "dns.qname", "matched_conditions" },
            positiveConditions: new[]
            {
                "A structured DNS qname must be present.",
                "The qname must target a known OAST, canary, or metadata service domain."
            },
            negativeConditions: new[]
            {
                "Do not alert on AnyText-only collaborator strings.",
                "Do not alert on unrelated domains that merely resemble these brands."
            },
            minimumConfidence: 68,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+query",
            falsePositives: new[] { "Security testing, SSRF labs, and cloud diagnostics can intentionally query these domains." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive canary or metadata query sample", "negative similar-looking domain sample" });

        public R185_CanaryOrMetadataDomainProbeRule() : base(Rule, Profile) { }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (!NetworkBatch176180Evidence.Dns(context.Record, out var query) || !IsCanaryOrMetadataQuery(query) || !_replay.Observe(context.Record, context.TimestampUtc))
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "known_canary_or_metadata_root", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The DNS question targeted a known OAST/canary root or a cloud metadata-related domain.",
                "Severity is Low because the query can indicate testing or SSRF exploration, but by itself it is weak signal.",
                "Security labs and cloud diagnostics often query these names intentionally.",
                "Review the source process and adjacent HTTP requests for SSRF or collaborator callbacks.",
                "Confirm whether the endpoint is part of a sanctioned security test."));

            return MatchDns(
                context,
                SeverityLevel.Low,
                "Canary or metadata DNS query observed",
                query,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "known-canary-or-metadata-root");
                },
                cooldownKey: $"{context.Record.Source}:{NetworkBatch166170Evidence.Key(query)}");
        }
    }
}
