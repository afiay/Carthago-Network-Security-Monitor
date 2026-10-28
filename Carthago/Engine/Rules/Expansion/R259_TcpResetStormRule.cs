// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R259_TcpResetStormRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R259_TcpResetStormRule : EvasionInfraPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R259",
            Name: "TCP Reset Storm",
            Category: "EvasionInfra",
            Description: "Detects tcp reset storm only when concrete network, process, or pipeline evidence is present; descriptor-only matches are suppressed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R259.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvasionInfraProfile(
            ruleId: "R259",
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
            threshold: 10,
            window: TimeSpan.FromMinutes(5),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+destination+behavior",
            falsePositives: new[] { "Load balancers, firewall policy changes, and application restarts can generate legitimate reset bursts." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "Threshold", "WindowSeconds" },
            requiredTests: new[] { "positive R259 evidence-gated sample", "negative R259 descriptor-only sample", "negative R259 missing telemetry sample" });

        public R259_TcpResetStormRule() : base(Rule, Profile) { }

        private readonly NetworkBatch256260Evidence.BoundedWindow _window = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch256260Evidence.TcpReset(r)) return NoMatch();
            var key = r.Source + "|" + r.Destination + "|" + r.DestinationPort;
            var count = _window.Observe(r, context.TimestampUtc, key, TimeSpan.FromMinutes(5));
            if (count < 10) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "tcp_rst_bit,distinct_packet_ids", "rule"),
                new("rule.windowCount", count.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("tcp.rst", "true", "network")
            };
            evidence.AddRange(AnalystContext("Repeated TCP RST-flag observations between the same endpoints.",
                "RST bursts can reflect ordinary service restarts or middlebox behavior.",
                "Legitimate load balancers and firewall changes may match.",
                "Inspect session termination and service health."));
            return MatchEvasionInfra(context, SeverityLevel.Medium, "TCP reset-flag burst",
                "TcpReset", evidence,
                c => { c.AddEvidence(0.34, "typed-tcp-flags"); c.AddEvidence(0.22, "distinct-packets"); c.AddEvidence(0.18, "window-threshold"); },
                count: count, window: Profile.Window, cooldownKey: key + ":tcp-reset");
        }
    }
}
