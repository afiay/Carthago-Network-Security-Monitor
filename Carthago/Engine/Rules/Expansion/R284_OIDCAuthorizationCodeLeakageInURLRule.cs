// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R284_OIDCAuthorizationCodeLeakageInURLRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R284_OIDCAuthorizationCodeLeakageInURLRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R284",
            Name: "OIDC Authorization Code Leakage In URL",
            Category: "IdentityAdvanced",
            Description: "Detects OIDC Authorization Code Leakage In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R284.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R284",
            Name = "OIDC Authorization Code Leakage In URL",
            Category = "IdentityAdvanced",
            Description = "Detects OIDC Authorization Code Leakage In URL only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires independently authenticated, provenance-verified outcome evidence from a trusted producer.", "Fail closed until that producer is integrated and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "authorization code", "code=", "oidc", "oauth", "redirect_uri", "leakage" },
            HostIndicators = Array.Empty<string>(),
            PathIndicators = new[] { "code=", "/callback", "/signin-oidc", "/oauth2/callback" },
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 1,
            Window = TimeSpan.FromMinutes(20),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "negative R284 apparent positive without trusted audit", "negative R284 spoofed and contradictory telemetry", "negative R284 privacy, replay and profile invariants" },
            RequireHttp = true,
        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R284_OIDCAuthorizationCodeLeakageInURLRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Current traffic capture cannot attest the identity outcome required by this rule.
            // Untrusted URI, port, header and Info indicators must never substitute for audit provenance.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "OIDC_CODE_LEAKAGE_PROVENANCE_UNAVAILABLE",
                "Trusted proof of authorization code disclosure to an unintended recipient is unavailable.");
        }
    }
}
