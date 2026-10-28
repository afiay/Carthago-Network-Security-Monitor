// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R288_NTLMv1AuthenticationObservedRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R288_NTLMv1AuthenticationObservedRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R288",
            Name: "NTLMv1 Authentication Observed",
            Category: "IdentityAdvanced",
            Description: "Detects NTLMv1 Authentication Observed only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R288.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R288",
            Name = "NTLMv1 Authentication Observed",
            Category = "IdentityAdvanced",
            Description = "Detects NTLMv1 Authentication Observed only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires verified protocol or exploit-specific evidence from a trusted captured-byte or audit producer.", "Fail closed until that producer is integrated and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "ntlmv1", "nt lm 0.12", "lmcompatibility", "ntlm version 1" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ntlm", "smb" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 445, 139, 80, 8080 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R288 apparent positive without trusted parser", "negative R288 spoofed and contradictory telemetry", "negative R288 privacy, replay and profile invariants" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R288_NTLMv1AuthenticationObservedRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, protocol labels, packet Info and generic request paths cannot attest this outcome.
            // Require validated captured-byte or server-audit provenance before enabling detections.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "NTLMV1_AUTH_PARSE_UNAVAILABLE",
                "Parsed and version-verified NTLMSSP authentication message or trusted server authentication audit is unavailable.");
        }
    }
}
