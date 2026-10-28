// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R344_WMIEventSubscriptionRemotePatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R344_WMIEventSubscriptionRemotePatternRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R344",
            Name: "WMI Event Subscription Remote Pattern",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R344 requires verified operation and provenance; packet-only indicators return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R344.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R344",
            Name = "WMI Event Subscription Remote Pattern",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R344 requires verified operation and provenance; packet-only indicators return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "WMI Event Subscription Remote Pattern requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "wmi event subscription", "__eventfilter", "commandlineeventconsumer", "wmiprvse" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "wmi", "dcom", "dcerpc" },
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
            RequiredTests = new[] { "positive R344 evidence-gated sample", "negative R344 descriptor-only sample", "negative R344 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R344_WMIEventSubscriptionRemotePatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Capture exposes network observations, not authenticated operation/outcome audit.
            // Do not promote text indicators, port hints or unverified enrichment to attack evidence.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "WMI_SUBSCRIPTION_AUDIT_UNAVAILABLE",
                "Remote WMI permanent event subscription requires authenticated namespace operation, filter/consumer binding, principal, target and result audit.");
        }
    }
}
