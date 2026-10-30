// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R363_CIArtifactArchiveDownloadBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R363_CIArtifactArchiveDownloadBurstRule : DevOpsSupplyChainPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R363",
            Name: "CI Artifact Archive Download Burst",
            Category: "DevOpsSupplyChain",
            Description: "Detects CI Artifact Archive Download Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R363.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R363",
            Name = "CI Artifact Archive Download Burst",
            Category = "DevOpsSupplyChain",
            Description = "Detects CI Artifact Archive Download Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Payload },
            RequiredFields = new[] { "source", "destination_or_host", "devops_or_secret_context" },
            EvidenceFields = new[] { "devops.host", "http.path", "token.pattern", "matched_conditions" },
            PositiveConditions = new[] { "CI Artifact Archive Download Burst requires concrete DevOpsSupplyChain telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "CI/CD jobs, package mirrors, vulnerability scanners, and authorized secret-management automations can trigger these rules." },
            TextIndicators = new[] { "ci artifact", "artifact archive", "download artifacts", "zip" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "/artifacts", "/jobs", "/builds" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 5,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+devopssupplychain+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R363 evidence-gated sample", "negative R363 descriptor-only sample", "negative R363 missing telemetry sample" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R363_CIArtifactArchiveDownloadBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var rejection = DevOpsRequestPrecisionEvidence.Reject(context.Record, context.TimestampUtc, "R363");
            if (rejection != null)
                return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence, rejection, "Rule-specific parser-attributed request evidence is unavailable.");
            return EvaluateSpec(context, Spec);
        }
    }
}
