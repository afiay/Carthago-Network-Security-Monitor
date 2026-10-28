// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R289_RADIUSAuthenticationFailureBurstRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R289_RADIUSAuthenticationFailureBurstRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R289",
            Name: "RADIUS Authentication Failure Burst",
            Category: "IdentityAdvanced",
            Description: "Detects RADIUS Authentication Failure Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R289.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R289",
            Name = "RADIUS Authentication Failure Burst",
            Category = "IdentityAdvanced",
            Description = "Detects RADIUS Authentication Failure Burst only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.Medium,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires verified protocol or exploit-specific evidence from a trusted captured-byte or audit producer.", "Fail closed until that producer is integrated and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "radius", "access-reject", "auth failure", "bad password", "nas-ip-address" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "radius" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 1812, 1813, 1645, 1646 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 74,
            WindowThreshold = 4,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R289 apparent positive without trusted parser", "negative R289 spoofed and contradictory telemetry", "negative R289 privacy, replay and profile invariants" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R289_RADIUSAuthenticationFailureBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, protocol labels, packet Info and generic request paths cannot attest this outcome.
            // Require validated captured-byte or server-audit provenance before enabling detections.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "RADIUS_ACCESS_REJECT_PARSE_UNAVAILABLE",
                "Parsed server-to-client RADIUS Access-Reject outcomes with authenticator and source correlation are unavailable.");
        }
    }
}
