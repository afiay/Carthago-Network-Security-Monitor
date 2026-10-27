// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R132_RapidCountryChangeForSourceIdentityRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R132_RapidCountryChangeForSourceIdentityRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private readonly NetworkBatch126130Window _observations = new();
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
            if (!NetworkBatch131135Evidence.HttpRequest(record) || !HasLoginContext(record))
                return NoMatch();

            var identity = ExtractIdentity(record);
            var country = NetworkBatch131135Evidence.CountryIso2(record);
            if (string.IsNullOrWhiteSpace(identity) || string.IsNullOrWhiteSpace(country))
                return NoMatch();

            var window = TimeSpan.FromSeconds(IntSetting(Rule.RuleId, "WindowSeconds", 600, 120, 7200));
            var threshold = IntSetting(Rule.RuleId, "Threshold", 3, 2, 20);
            var identityKey = NetworkBatch131135Evidence.Fingerprint(identity);
            var key = $"{Rule.RuleId}:{identityKey}:{BestHost(record)}";
            var distinctCountries = _observations.Add(key, record.Id, country, false, context.TimestampUtc, window).Distinct;
            if (distinctCountries < threshold)
                return NoMatch();

            var proxy = record.IsVpn == true || record.IsProxy == true;
            var matchedConditions = new List<string> { "identity_country_change", "threshold_reached" };
            if (proxy) matchedConditions.Add("vpn_or_proxy_attributed");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("identity.subject", "sha256:" + identityKey, "identity"),
                new("geo.country", country, "geoip"),
                new("count", distinctCountries.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)window.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("http.path", "[login-endpoint]", "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                "A pseudonymized login identity appeared with multiple attributed source-country codes.",
                "Severity is Medium because rapid country changes may indicate account compromise or geo-IP instability.",
                "VPN egress changes, carrier routing, and geo-IP updates may mimic impossible travel.",
                "Check independently sourced login telemetry and the geo-IP database timestamp.",
                "Correlate successful sessions and MFA challenges before escalation."));

            return MatchIdentityAccess(context, SeverityLevel.Medium,
                "Identity observed from rapidly changing countries", "GeoVelocity",
                evidenceItems, confidence =>
                {
                    confidence.AddEvidence(0.26, "identity-context");
                    confidence.AddEvidence(0.20, "multiple-countries");
                    confidence.AddEvidence(0.16, "threshold-reached");
                }, distinctCountries, window, identityKey + ":" + BestHost(record));
        }

    }
}
