// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R262_SuspiciousPacketFragmentationRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R262_SuspiciousPacketFragmentationRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R262",
            Name: "Suspicious Packet Fragmentation",
            Category: "EvasionInfra",
            Description: "Detects suspicious packet fragmentation only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R262.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R262",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            requiredFields: new[] { "source", "destination_or_host", "protocol_or_process_or_info" },
            evidenceFields: new[] { "network.source", "network.destination", "process.name", "event.info", "matched_conditions" },
            positiveConditions: new[]
            {
                "The rule must observe concrete telemetry evidence tied to the named behavior.",
                "The event must include a source and either a destination/host, process, protocol, or pipeline component.",
                "Generic descriptor text alone must not produce a match."
            },
            negativeConditions: new[]
            {
                "Do not alert when the required telemetry fields are absent.",
                "Do not alert on generic logs that mention the concept but lack network/process/pipeline evidence."
            },
            minimumConfidence: 82,
            threshold: 2,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Path MTU issues, tunnels, and legacy devices can fragment traffic; tune known tunnel endpoints." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R262 evidence-gated sample", "negative R262 descriptor-only sample", "negative R262 missing telemetry sample" });

        public R262_SuspiciousPacketFragmentationRule() : base(Rule, Profile) { }

        private readonly NetworkBatch256260Evidence.BoundedWindow _fragments = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch261265Evidence.TinyFragment(r)) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + r.IpVersion;
            var count = _fragments.Observe(r, context.TimestampUtc, key, TimeSpan.FromMinutes(10));
            if (count < 2) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_ipv4_noninitial_tiny_fragment,distinct_packet_ids", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule")
            };
            evidence.AddRange(AnalystContext("Two distinct typed tiny noninitial IPv4 fragments were reported within 10 minutes.",
                "Tiny fragmentation can interfere with inspection, but does not establish overlap or successful evasion.",
                "The current PacketHandler drops fragments: these positives are typed contract-only until capture integration exists.",
                "Inspect capture-path fragment telemetry before considering promotion."));
            return MatchEvasionInfra(context, SeverityLevel.High, "Typed tiny-fragment observations (capture reachability unverified)",
                "Fragmentation", evidence, c => { c.AddEvidence(0.34, "typed-fragment"); c.AddEvidence(0.22, "distinct-packets"); c.AddEvidence(0.18, "bounded-window"); },
                count: count, window: Profile.Window, cooldownKey: key + ":tiny-fragments");
        }
    }
}
