// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R273_ImpossibleTravelAuthenticationSequenceRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R273_ImpossibleTravelAuthenticationSequenceRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R273",
            Name: "Impossible Travel Authentication Sequence",
            Category: "IdentityAdvanced",
            Description: "Detects Impossible Travel Authentication Sequence only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R273.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R273",
            Name = "Impossible Travel Authentication Sequence",
            Category = "IdentityAdvanced",
            Description = "Detects Impossible Travel Authentication Sequence only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires trusted account-linked successful IdP sign-in events, timestamps and independently geolocated source IPs.", "Network packet GeoIP and text labels cannot attest to an authentication sequence." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "impossible travel", "travel", "geo", "country", "login", "signin", "authentication", "session" },
            HostIndicators = new[] { "okta", "login.microsoftonline.com", "entra", "auth0", "duo", "pingidentity" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 2,
            Window = TimeSpan.FromMinutes(45),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R273 evidence-gated sample", "negative R273 descriptor-only sample", "negative R273 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R273_ImpossibleTravelAuthenticationSequenceRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // GeoIP on a network packet is not a successful identity-provider sign-in.
            // No trusted account/outcome/session authentication event is present.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "AUTHENTICATED_SIGNIN_SEQUENCE_UNAVAILABLE",
                "Impossible travel requires verified account-linked sign-ins, times and locations.");
        }
    }
}
