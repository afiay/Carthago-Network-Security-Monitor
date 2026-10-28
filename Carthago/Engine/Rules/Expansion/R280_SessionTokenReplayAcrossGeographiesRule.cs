// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R280_SessionTokenReplayAcrossGeographiesRule.cs
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R280_SessionTokenReplayAcrossGeographiesRule : IdentityAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R280",
            Name: "Session Token Replay Across Geographies",
            Category: "IdentityAdvanced",
            Description: "Detects Session Token Replay Across Geographies only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R280.Enabled",
            EnabledByDefault: true);

        private static readonly PrecisionRuleSpec Spec = new()
        {
            RuleId = "R280",
            Name = "Session Token Replay Across Geographies",
            Category = "IdentityAdvanced",
            Description = "Detects Session Token Replay Across Geographies only when concrete telemetry gates, rule-specific indicators, and threshold/cooldown controls are satisfied; descriptor-only events return NoMatch.",
            Severity = SeverityLevel.High,
            RequiredTelemetry = new[] { RuleTelemetryKind.Identity, RuleTelemetryKind.Http, RuleTelemetryKind.GeoIp },
            RequiredFields = new[] { "source", "identity_or_user", "destination_or_host", "auth_or_http_context" },
            EvidenceFields = new[] { "identity.signal", "network.source", "network.destination", "matched_conditions", "rule.windowCount" },
            PositiveConditions = new[] { "Requires authenticated session reuse events with nonreversible token fingerprint, account, timestamp and source geolocation.", "Fail closed until a verified producer is connected and approved." },
            NegativeConditions = new[] { "Do not match on rule names, category labels, or generic scanner banners alone.", "Do not match when source/destination context is absent.", "Do not match approved administrative, CI/CD, backup, mail migration, or monitoring paths unless explicit high-risk evidence is present." },
            FalsePositives = new[] { "Legitimate travel, VPN egress, identity-provider retries, or approved admin sessions can resemble these events." },
            TextIndicators = new[] { "session token replay", "token replay", "same token", "cookie", "sessionid", "bearer", "geo" },
            HostIndicators = Array.Empty<string>(),
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
            Window = TimeSpan.FromMinutes(30),
            Cooldown = TimeSpan.FromMinutes(20),
            DistinctBy = "source+destination+identityadvanced+behavior",
            TuningKnobs = new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedServiceAccounts" },
            RequiredTests = new[] { "positive R280 evidence-gated sample", "negative R280 descriptor-only sample", "negative R280 missing telemetry sample" },

        };

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(Spec);

        public R280_SessionTokenReplayAcrossGeographiesRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            // GeoIP changes and cookie text do not prove reuse of the same authenticated session. Require protected token fingerprints and trusted session audit events.
            // No trusted producer for this event family is connected to TrafficRecord.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "SESSION_REPLAY_AUDIT_UNAVAILABLE",
                "GeoIP changes and cookie text do not prove reuse of the same authenticated session. Require protected token fingerprints and trusted session audit events.");
        }
    }
}
