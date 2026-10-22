// SPDX-License-Identifier: MIT
// File: Engine/Rules/IotOt/R121_BACnetDiscoveryFromNonAdminHostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.IotOt
{
    public sealed class R121_BACnetDiscoveryFromNonAdminHostRule : IotOtPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R121",
            Name: "BACnet Discovery from Non-Admin Host",
            Category: "IotOt",
            Description: "Detects BACnet discovery activity only when it carries real who-is or discovery semantics from non-admin-like sources or crosses unexpected boundaries.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R121.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateIotOtProfile(
            ruleId: "R121",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.OtIcsProtocol, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "iot_or_ot_context" },
            evidenceFields: new[] { "matched_conditions", "network.destinationPort", "process.name" },
            positiveConditions: new[]
            {
                "The record must contain BACnet discovery semantics such as who-is or broadcast discovery.",
                "External boundaries or non-admin-like internal sources should drive detection.",
                "Ordinary BACnet i-am chatter or clearly administrative tooling should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on BACnet mentions without discovery semantics.",
                "Do not alert on i-am-only traffic.",
                "Do not alert on clearly administrative BACnet processes when no other red flags are present."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(15),
            distinctBy: "source+destination",
            falsePositives: new[]
            {
                "Approved BACnet admin hosts and controllers should be shadowed through Approved.AdminHosts, Approved.BacnetControllers, or Approved.OtSegments."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive bacnet discovery sample",
                "negative admin bacnet discovery sample",
                "negative i-am-only sample"
            });

        public R121_BACnetDiscoveryFromNonAdminHostRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsBacnetContext(record))
                return NoMatch();

            var text = Text(record);
            var discoveryContext = text.IndexOf("who-is", StringComparison.OrdinalIgnoreCase) >= 0
                                   || text.IndexOf("whois", StringComparison.OrdinalIgnoreCase) >= 0
                                   || text.IndexOf("discover", StringComparison.OrdinalIgnoreCase) >= 0
                                   || IsMulticastOrBroadcast(record.Destination);
            var iamOnly = !discoveryContext
                          && (text.IndexOf("i-am", StringComparison.OrdinalIgnoreCase) >= 0
                              || text.IndexOf("iam", StringComparison.OrdinalIgnoreCase) >= 0);
            if (!discoveryContext || iamOnly)
                return NoMatch();

            var externalBoundary = IsExternalAddress(record.Source) || IsExternalAddress(record.Destination);
            var adminLike = IsLikelyBacnetAdminProcess(record.ProcessName, record.Info);
            if (!externalBoundary && adminLike)
                return NoMatch();

            var matchedConditions = new List<string> { "bacnet_discovery_context" };
            if (externalBoundary) matchedConditions.Add("external_boundary");
            if (!adminLike) matchedConditions.Add("non_admin_like_source");
            if (IsMulticastOrBroadcast(record.Destination)) matchedConditions.Add("broadcast_or_multicast_target");

            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidenceItems.AddRange(AnalystContext(
                externalBoundary
                    ? "BACnet discovery semantics crossed an unexpected external boundary."
                    : "BACnet discovery semantics originated from a source that does not look like known admin or BMS tooling.",
                "Severity is High because BACnet discovery from unexpected sources can expose building-control inventory and precede OT reconnaissance.",
                "Approved BMS tooling and BACnet controllers should be shadowed through environment tuning.",
                "Validate whether the source is an approved BACnet admin host or BMS process.",
                "Review whether the destination scope and discovery timing align with maintenance activity."));

            return MatchIot(
                context,
                SeverityLevel.High,
                "BACnet discovery from unexpected or non-admin source",
                "BACnet",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.40, "bacnet-discovery-context");
                    if (!adminLike) confidence.AddEvidence(0.20, "non-admin-like-source");
                    if (externalBoundary) confidence.AddCorrelation(0.12, "external-boundary");
                    if (IsMulticastOrBroadcast(record.Destination)) confidence.AddEvidence(0.12, "broadcast-or-multicast-target");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
