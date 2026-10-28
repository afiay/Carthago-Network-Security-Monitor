// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R286_LDAPSimpleBindOverCleartextExternalRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R286_LDAPSimpleBindOverCleartextExternalRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R286",
            Name: "LDAP Simple Bind Over Cleartext External",
            Category: "IdentityAdvanced",
            Description: "Detects LDAP Simple Bind Over Cleartext External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R286.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R286",
            Name = "LDAP Simple Bind Over Cleartext External",
            Category = "IdentityAdvanced",
            Description = "Detects LDAP Simple Bind Over Cleartext External only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires verified protocol or exploit-specific evidence from a trusted captured-byte or audit producer.", "Fail closed until that producer is integrated and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "ldap simple bind", "simple bind", "cleartext", "bindrequest", "password" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = new[] { "ldap" },
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = new[] { 389 },
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R286 apparent positive without trusted parser", "negative R286 spoofed and contradictory telemetry", "negative R286 privacy, replay and profile invariants" },
            RequireCleartext = true,
            RequireCrossBoundary = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R286_LDAPSimpleBindOverCleartextExternalRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Ports, protocol labels, packet Info and generic request paths cannot attest this outcome.
            // Require validated captured-byte or server-audit provenance before enabling detections.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "LDAP_SIMPLE_BIND_PARSE_UNAVAILABLE",
                "Verified LDAP BER simple BindRequest with client-to-server direction and approved boundary provenance is unavailable.");
        }
    }
}
