// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R128_NetworkApplianceManagementExposureRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R128_NetworkApplianceManagementExposureRule : IdentityAccessPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R128",
            Name: "Network Appliance Management Exposure",
            Category: "IdentityAccess",
            Description: "Detects cross-boundary access to explicit network-appliance management portals with vendor or appliance context.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R128.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIdentityAccessProfile(
            ruleId: "R128",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must cross an internal-external boundary.",
                "The host, path, or payload must indicate a network appliance or VPN appliance management interface.",
                "Generic software vendor websites should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on documentation or download sites that mention vendors but do not expose management paths.",
                "Do not alert on generic public logins with no appliance context."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved appliance management portals, MSP remote support, or sanctioned public admin interfaces can match."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive appliance management portal sample",
                "negative vendor documentation sample"
            });

        public R128_NetworkApplianceManagementExposureRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            if (!IsApplianceManagementPortal(record))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "appliance_management_portal", "cross_boundary" };
            if (ContainsAny(Text(record), "vpn", "sslvpn", "webvpn")) matchedConditions.Add("vpn_appliance");
            if (outboundToExternal) matchedConditions.Add("outbound_to_external");
            if (inboundFromExternal) matchedConditions.Add("inbound_from_external");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                outboundToExternal
                    ? "An internal client reached an internet-hosted network appliance management interface."
                    : "An external source reached an internal network appliance management interface.",
                "Severity is High because exposed appliance management planes often control VPN, routing, or firewall policy.",
                "Approved MSP or sanctioned public management interfaces can match. Validate whether the interface is expected and adequately restricted.",
                "Confirm whether the appliance and management path are approved for this trust boundary.",
                "Inspect authentication, MFA, and configuration-change activity near the same time."));

            return MatchIdentityAccess(
                context,
                SeverityLevel.High,
                "Network appliance management interface reached across boundary",
                "ApplianceManagement",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.34, "http-context");
                    confidence.AddEvidence(0.26, "appliance-management-context");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                    if (ContainsAny(Text(record), "vpn", "sslvpn", "webvpn")) confidence.AddCorrelation(0.10, "vpn-appliance");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
