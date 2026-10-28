// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R258_IcmpDestinationUnreachableSpikeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R258_IcmpDestinationUnreachableSpikeRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R258",
            Name: "ICMP Destination Unreachable Spike",
            Category: "EvasionInfra",
            Description: "Detects icmp destination unreachable spike only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R258.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R258",
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
            minimumConfidence: 75,
            threshold: 8,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Network changes, firewall tests, or outage triage can legitimately produce unreachable bursts." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R258 evidence-gated sample", "negative R258 descriptor-only sample", "negative R258 missing telemetry sample" });

        public R258_IcmpDestinationUnreachableSpikeRule() : base(Rule, Profile) { }

        private readonly NetworkBatch256260Evidence.BoundedWindow _window = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch256260Evidence.IcmpUnreachable(r)) return NoMatch();
            var count = _window.Observe(r, context.TimestampUtc, r.Source + "|" + r.Destination + "|" + r.IcmpTypeCode, TimeSpan.FromMinutes(5));
            if (count < 8) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "typed_icmp_unreachable,distinct_packet_ids", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("icmp.typeCode", r.IcmpTypeCode!.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "network")
            };
            evidence.AddRange(AnalystContext("Repeated captured ICMP destination-unreachable type/code observations.",
                "Unreachable bursts may reflect routing faults or firewall policy, not necessarily evasion.",
                "Maintenance and outage triage can produce benign bursts.",
                "Inspect interface counters, routing and firewall changes."));
            return MatchEvasionInfra(context, SeverityLevel.Medium, "Typed ICMP unreachable burst",
                "IcmpUnreachable", evidence,
                c => { c.AddEvidence(0.34, "typed-icmp"); c.AddEvidence(0.22, "distinct-packets"); c.AddEvidence(0.18, "window-threshold"); },
                count: count, window: Profile.Window, cooldownKey: r.Source + ":" + r.Destination + ":icmp-unreachable");
        }
    }
}
