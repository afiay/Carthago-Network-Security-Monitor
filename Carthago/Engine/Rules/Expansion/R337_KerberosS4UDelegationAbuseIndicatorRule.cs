// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R337_KerberosS4UDelegationAbuseIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R337_KerberosS4UDelegationAbuseIndicatorRule : ActiveDirectoryWindowsPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R337",
            Name: "Kerberos S4U Delegation Abuse Indicator",
            Category: "ActiveDirectoryWindows",
            Description: "Candidate R337 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R337.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R337",
            Name = "Kerberos S4U Delegation Abuse Indicator",
            Category = "ActiveDirectoryWindows",
            Description = "Candidate R337 requires authenticated protocol operation and outcome provenance; packet-only indicators cannot establish the named behavior.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Identity, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "windows_protocol_context" },
            EvidenceFields = new[] { "ad.protocol", "network.source", "network.destination", "matched_conditions" },
            PositiveConditions = new[] { "Kerberos S4U Delegation Abuse Indicator requires concrete ActiveDirectoryWindows telemetry, not descriptor text.", "The source and destination or identity context must be present.", "At least two independent rule-specific signals must be present, or the rule-specific threshold must be met." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Domain controller administration, vulnerability scanning, GPO operations, and backup tooling can resemble some Windows/AD behaviors." },
            TextIndicators = new[] { "s4u", "delegation", "s4u2proxy", "s4u2self", "constrained delegation" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "kerberos" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 88 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+activedirectorywindows+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R337 evidence-gated sample", "negative R337 descriptor-only sample", "negative R337 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R337_KerberosS4UDelegationAbuseIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // No authenticated protocol operation/outcome producer is connected to the capture path.
            // Packet text, generic service ports and unverified enrichment cannot prove this behavior.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "KERBEROS_S4U_AUDIT_UNAVAILABLE",
                "Kerberos port and S4U vocabulary do not prove delegation abuse. Require validated KDC S4U2Self/S4U2Proxy exchanges, principal, service, ticket outcome and approved delegation policy.");
        }
    }
}
