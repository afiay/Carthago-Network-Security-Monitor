// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R132_RapidCountryChangeForSourceIdentityRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R132_RapidCountryChangeForSourceIdentityRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R132",
            Name: "Rapid Country Change For Source Identity",
            Category: "IdentityAccess",
            Description: "Detects login-related events where the same extracted identity appears from multiple countries in a short window.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R132.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R132",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Authentication, RuleTelemetryKind.GeoIp },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "identity_context" },
            evidenceFields: new[] { "matched_conditions", "identity.subject", "geo.country" },
            positiveConditions: new[]
            {
                "The record must contain login or authentication context.",
                "A stable source identity must be extracted from the event.",
                "The same identity must appear from multiple countries within the configured window."
            },
            negativeConditions: new[]
            {
                "Do not alert when the country is missing.",
                "Do not alert on repeated activity from a single country."
            },
            minimumConfidence: 72,
            threshold: 3,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "identity",
            falsePositives: new[]
            {
                "VPN egress changes, mobile carrier routing, or geoip drift can create noisy country changes."
            },
            tuningKnobs: new[] { "Mode", "Threshold", "WindowSeconds", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive multi-country identity sample",
                "negative single-country identity sample"
            });

        public R132_RapidCountryChangeForSourceIdentityRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasLoginContext(record))
                return NoMatch();

            var identity = ExtractIdentity(record);
            var country = SourceCountry(record);
            if (string.IsNullOrWhiteSpace(identity) || string.IsNullOrWhiteSpace(country))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 600, 120, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 20);
            var distinctCountries = CountDistinctValues($"{Rule.RuleId}:{identity}", country, context.TimestampUtc, window);
            if (distinctCountries < threshold)
                return NoMatch();

            var matchedConditions = new List<string> { "identity_country_change", "threshold_reached" };
            if (ContainsAny(Text(record), "vpn", "proxy")) matchedConditions.Add("vpn_or_proxy_context");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("identity.subject", identity, "identity"),
                new("geo.country", country, "geoip"),
                new("count", distinctCountries.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "The same login identity appeared from multiple countries within a short period.",
                "Severity is Medium because rapid country churn can indicate credential theft, session hijacking, or aggressive proxy hopping.",
                "VPN egress changes, travel, or mobile routing can create noise. Validate the identity against known VPN or roaming patterns.",
                "Confirm whether the identity was expected to use a VPN, proxy, or roaming client.",
                "Review successful logins, MFA prompts, and session issuance for this identity."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.Medium,
                "Identity observed from rapidly changing countries",
                "GeoVelocity",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "identity-context");
                    confidence.AddEvidence(0.20, "multiple-countries");
                    confidence.AddEvidence(0.16, "threshold-reached");
                    if (ContainsAny(Text(record), "vpn", "proxy")) confidence.AddCorrelation(0.08, "vpn-or-proxy-context");
                },
                distinctCountries,
                window,
                identity);
        }
    }
}
