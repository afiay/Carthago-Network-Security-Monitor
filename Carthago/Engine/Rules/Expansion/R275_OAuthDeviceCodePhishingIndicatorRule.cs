// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R275_OAuthDeviceCodePhishingIndicatorRule.cs
using System;
using System.Collections.Concurrent;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.TrustedAudit;

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
        private static readonly ConcurrentDictionary<string, DateTime> PromotionCooldowns =
            new(StringComparer.Ordinal);
        private const int MaxPromotionCooldownKeys = 8192;

        public R275_OAuthDeviceCodePhishingIndicatorRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            if (context.TrustedR275Capability != null
                && context.TrustedR275PromotionAuthorization != null)
            {
                var evt = CreateDetectionEvent(
                    context,
                    SeverityLevel.High,
                    "Admin-confirmed compromised OAuth device-code sign-in corroborated by two independent trusted audit issuers.",
                    new[]
                    {
                        new DetectionEvidenceItem(
                            "identity.signal",
                            "admin-confirmed-device-code-compromise",
                            "trusted-idp-audit"),
                        new DetectionEvidenceItem(
                            "identity.audit.independentIssuers",
                            "2",
                            "trusted-idp-audit"),
                        new DetectionEvidenceItem(
                            "identity.networkBinding",
                            "exact-flow-and-time",
                            "trusted-idp-audit"),
                        new DetectionEvidenceItem(
                            "identity.promotionPolicy",
                            OAuthDeviceFlowPromotionAuthorization.PolicyId,
                            "promotion-policy")
                    },
                    confidence => confidence
                        .AddEvidence(0.65, "admin-confirmed-device-code-compromise")
                        .AddCorrelation(0.25, "two-independent-signed-audit-receipts")
                        .AddEvidence(0.05, "exact-network-flow-binding"));

                var cooldown = Profile.Cooldown ?? TimeSpan.Zero;
                if (cooldown > TimeSpan.Zero
                    && IsPromotionSuppressed(
                        context.TrustedR275Capability.TraceHash,
                        context.TimestampUtc,
                        cooldown,
                        out var remaining))
                {
                    SuppressForCooldown(
                        evt,
                        $"R275 trusted-evidence cooldown or bounded-state gate active for {remaining.TotalSeconds:F0}s.");
                    EvidenceBuilder.AppendEvidence(
                        evt,
                        "suppression.remainingSeconds",
                        Math.Ceiling(remaining.TotalSeconds)
                            .ToString(System.Globalization.CultureInfo.InvariantCulture),
                        "rule");
                }

                return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
            }

            if (context.TrustedR275Capability != null)
            {
                // The capability proves that the exact packet/context reached the
                // independently signed R275 audit boundary. Promotion remains a
                // separate policy gate: plumbing trusted evidence into evaluation
                // must not silently create a live alert.
                return NoMatch(RuleNoMatchReasonCategory.RuntimePrecisionGate,
                    "TRUSTED_DEVICE_CODE_CAPABILITY_PRESENT_NOT_PROMOTED",
                    "Trusted R275 audit capability is present for this exact flow, but alert promotion is not yet authorized.");
            }

            // Device-code initiation, even when query parameters mention user_code,
            // is not evidence of phishing. HTTPS payload is not decrypted by the
            // packet capture path and there is no trusted IdP device-flow audit.
            return NoMatch(RuleNoMatchReasonCategory.InsufficientEvidence,
                "TRUSTED_DEVICE_CODE_ABUSE_EVENT_UNAVAILABLE",
                "A verified IdP audit event or independently corroborated phishing action is required.");
        }

        private static bool IsPromotionSuppressed(
            string traceHash,
            DateTime now,
            TimeSpan cooldown,
            out TimeSpan remaining)
        {
            remaining = TimeSpan.Zero;

            if (PromotionCooldowns.TryGetValue(traceHash, out var last))
            {
                var delta = now - last;
                if (delta <= TimeSpan.Zero || delta < cooldown)
                {
                    remaining = delta <= TimeSpan.Zero
                        ? cooldown
                        : cooldown - delta;
                    return true;
                }
            }

            if (PromotionCooldowns.Count >= MaxPromotionCooldownKeys
                && !PromotionCooldowns.ContainsKey(traceHash))
            {
                var staleBefore = now - cooldown - cooldown;
                foreach (var entry in PromotionCooldowns)
                    if (entry.Value < staleBefore)
                        PromotionCooldowns.TryRemove(entry.Key, out _);

                if (PromotionCooldowns.Count >= MaxPromotionCooldownKeys)
                {
                    remaining = cooldown;
                    return true;
                }
            }

            PromotionCooldowns[traceHash] = now;
            return false;
        }
    }
}
