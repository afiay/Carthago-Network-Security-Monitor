// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R274_MFAPushFatiguePatternRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R274_MFAPushFatiguePatternRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R274",
            Name: "MFA Push Fatigue Pattern",
            Category: "IdentityAdvanced",
            Description: "Detects MFA Push Fatigue Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R274.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R274",
            Name = "MFA Push Fatigue Pattern",
            Category = "IdentityAdvanced",
            Description = "Detects MFA Push Fatigue Pattern only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires trusted MFA prompt IDs, account, timestamps, delivery status and denial/approval outcomes.", "HTTP requests and packet descriptions cannot establish MFA fatigue." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "mfa push", "push fatigue", "mfa denied", "mfa prompt", "number matching", "push notification", "duo push" },
            HostIndicators = new[] { "duo.com", "okta", "login.microsoftonline.com" },
            PathIndicators = Array.Empty<string>(),
            ProcessIndicators = Array.Empty<string>(),
            ProtocolIndicators = Array.Empty<string>(),
            Methods = Array.Empty<string>(),
            TokenKinds = Array.Empty<string>(),
            Ports = Array.Empty<int>(),
            MinimumBytes = 0L,
            MinimumSignals = 2,
            MinimumConfidence = 78,
            WindowThreshold = 3,
            Window = TimeSpan.FromMinutes(10),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R274 evidence-gated sample", "negative R274 descriptor-only sample", "negative R274 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R274_MFAPushFatiguePatternRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // Packet HTTP/Info fields do not carry authenticated MFA push event IDs,
            // delivery/outcome status or account correlation.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "AUTHENTICATED_MFA_PUSH_EVENTS_UNAVAILABLE",
                "MFA fatigue requires trusted distinct prompts and their outcomes for one account.");
        }
    }
}
