// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R345_DCOMMMC20LateralIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R345_DCOMMMC20LateralIndicatorRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R345",
            Name: "DCOM MMC20 Lateral Indicator",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R345 requires verified operation and provenance; packet-only indicators return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R345.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R345",
            Name = "DCOM MMC20 Lateral Indicator",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R345 requires verified operation and provenance; packet-only indicators return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "DCOM MMC20 Lateral Indicator requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "mmc20.application", "dcom", "executeShellCommand", "lateral" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "dcom", "dcerpc" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 135, 445 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R345 evidence-gated sample", "negative R345 descriptor-only sample", "negative R345 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R345_DCOMMMC20LateralIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Capture exposes network observations, not authenticated operation/outcome audit.
            // Do not promote text indicators, port hints or unverified enrichment to attack evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "DCOM_MMC20_AUDIT_UNAVAILABLE",
                "MMC20 DCOM lateral execution requires validated COM activation, authenticated remote principal and ExecuteShellCommand invocation/outcome.");
        }
    }
}
