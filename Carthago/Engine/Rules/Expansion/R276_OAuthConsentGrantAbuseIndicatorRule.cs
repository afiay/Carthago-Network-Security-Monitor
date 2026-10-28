// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R276_OAuthConsentGrantAbuseIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R276_OAuthConsentGrantAbuseIndicatorRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R276",
            Name: "OAuth Consent Grant Abuse Indicator",
            Category: "IdentityAdvanced",
            Description: "Detects OAuth Consent Grant Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R276.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R276",
            Name = "OAuth Consent Grant Abuse Indicator",
            Category = "IdentityAdvanced",
            Description = "Detects OAuth Consent Grant Abuse Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires authenticated IdP consent-grant audit with tenant, app, actor, scopes and grant outcome; URI text alone is not a grant.", "Fail closed until a verified producer is connected and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "oauth consent", "admin_consent", "consent grant", "offline_access", "mail.read", "files.read.all", "app role assignment" },
            HostIndicators = new[] { "login.microsoftonline.com", "graph.microsoft.com" },
            PathIndicators = new[] { "/adminconsent", "/consent", "/oauth2/v2.0/authorize" },
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
            RequiredTests = new[] { "positive R276 evidence-gated sample", "negative R276 descriptor-only sample", "negative R276 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R276_OAuthConsentGrantAbuseIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // A consent URL or OAuth scope string does not establish an application grant. Require signed IdP audit records with tenant, app, actor, scopes and grant outcome.
            // No trusted producer for this event family is connected to TrafficRecord.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "AUTHENTICATED_CONSENT_GRANT_AUDIT_UNAVAILABLE",
                "A consent URL or OAuth scope string does not establish an application grant. Require signed IdP audit records with tenant, app, actor, scopes and grant outcome.");
        }
    }
}
