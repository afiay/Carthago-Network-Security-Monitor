// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R388_CloudflareTunnelCreationIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R388_CloudflareTunnelCreationIndicatorRule : CloudInfrastructurePrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R388",
            Name: "Cloudflare Tunnel Creation Indicator",
            Category: "CloudInfrastructure",
            Description: "Detects Cloudflare Tunnel Creation Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R388.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R388",
            Name = "Cloudflare Tunnel Creation Indicator",
            Category = "CloudInfrastructure",
            Description = "Detects Cloudflare Tunnel Creation Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.CloudAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_cloud_host", "cloud_action_or_api_path" },
            EvidenceFields = new[] { "cloud.provider", "cloud.api", "http.path", "matched_conditions" },
            PositiveConditions = new[] { "Cloudflare Tunnel Creation Indicator requires observable CloudInfrastructure telemetry and will not match descriptor text alone.", "Source and destination, host, process, protocol, path, port, or payload evidence must be present.", "The configured signal count and time-window threshold must be satisfied before a DetectionEvent is emitted." },
            NegativeConditions = new[] { "Do not match on product names, rule names, documentation text, or generic banners alone.", "Do not match when source/destination context is absent or when the traffic is inside an approved management path.", "Do not match known monitoring, backup, CI/CD, inventory, scanner, or administrative workflows unless rule-specific high-risk evidence remains." },
            FalsePositives = new[] { "Approved infrastructure automation, CI/CD deploy jobs, cloud inventory tools, or cloud security scanners may perform similar API actions; approve known service accounts and management hosts." },
            TextIndicators = Array.Empty<string>(),
            HostIndicators = new[] { "api.cloudflare.com" },
            PathIndicators = new[] { "/client/v4/accounts/", "/cfd_tunnel" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = new[] { "post" },
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(15),
            Cooldown = TimeSpan.FromMinutes(30),
            DistinctBy = "source+destination+cloudinfrastructure+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedCloudAccounts", "ApprovedServiceAccounts", "ApprovedAutomationHosts", "AllowedCloudRegions" },
            RequiredTests = new[] { "positive R388 evidence-gated sample", "negative R388 descriptor-only sample", "negative R388 missing telemetry sample", "negative R388 approved-admin sample" },
            RequireHttp = true,
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R388_CloudflareTunnelCreationIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // SOURCE CANDIDATE — UNVERIFIED. Provider request shape alone
            // cannot establish authentication, success or malicious intent.
            var rejection = CloudProviderRequestEvidence.Reject(context.Record, context.TimestampUtc, "R388");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection,
                    "Rule-specific packet evidence or trusted provider audit is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
