// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R275_OAuthDeviceCodePhishingIndicatorRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R275_OAuthDeviceCodePhishingIndicatorRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R275",
            Name: "OAuth Device Code Phishing Indicator",
            Category: "IdentityAdvanced",
            Description: "Detects OAuth Device Code Phishing Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R275.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R275",
            Name = "OAuth Device Code Phishing Indicator",
            Category = "IdentityAdvanced",
            Description = "Detects OAuth Device Code Phishing Indicator only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Http },
            RequiredFields = new[] { "source", "destination_or_host", "http_any" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires a trusted IdP device-flow abuse event and independently corroborated phishing evidence.", "A device-code endpoint request or query parameters alone are not phishing proof." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "device code", "device_code", "verification_uri", "user_code", "oauth device", "phishing" },
            HostIndicators = new[] { "login.microsoftonline.com", "microsoftonline.com", "oauth" },
            PathIndicators = new[] { "/devicecode", "/device/code", "/oauth2/devicecode" },
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
            RequiredTests = new[] { "positive R275 evidence-gated sample", "negative R275 descriptor-only sample", "negative R275 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R275_OAuthDeviceCodePhishingIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Device-code initiation, even when query parameters mention user_code,
            // is not evidence of phishing. HTTPS payload is not decrypted by the
            // packet capture path and there is no trusted IdP device-flow audit.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE",
                "A verified IdP audit event or independently corroborated phishing action is required.");
        }
    }
}
