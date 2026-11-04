// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2606.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R707_CompetingDhcpResponderDatagramsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R707",
            Name: "Two distinct private DHCP responders target one client",
            Category: "LocalDiscoveryWireless",
            Description: "Two distinct private source addresses send coherent UDP/67-to-68 datagrams to the same private client within 10 seconds. The packets are not parsed as DHCP OFFER/ACK and do not establish rogue-server status or malicious DNS/gateway options.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R707.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R707",
            Name = "Two distinct private DHCP responders target one client",
            Category = "LocalDiscoveryWireless",
            Description = "Workbook R2606: the workbook expects DHCP message types and unauthorized option values. Carthago currently exposes only packet/port metadata here, so this rule requires two distinct unicast DHCP-server-port responders and does not duplicate R462's single-event generic rogue-offer candidate.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "source.port", "destination.port" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed producer fields and this rule's independent exact predicate.",
                "Bounded correlation uses unique packet IDs and UTC ordering where multiple observations are required.",
                "Only the observable packet, flow, parser, or best-effort process association is claimed."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory protocol fields, wrong network direction, and Info-only indicators.",
                "Reject packet-ID replay, out-of-order state, stale windows, and cooldown repeats.",
                "Do not infer authentication, exploit success, file writes, command lines, transfer completion, or compromise."
            },
            FalsePositives = new[] { "Legitimate redundant DHCP servers, failover pairs, relays, migrations, and test networks can produce competing responder traffic." },
            MinimumConfidence = 80,
            WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "client+distinct_dhcp_responder_sources",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped case and benign near miss",
                "wrong or missing telemetry and contradictory protocol fields",
                "duplicate packet ID and out-of-order timestamp where relevant",
                "window expiry and cooldown behavior",
                "privacy/redaction, registry uniqueness, Candidate Shadow, and non-convergence"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research706DistinctWindow _responders = new();

        public R707_CompetingDhcpResponderDatagramsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.Udp(r)
                || r.SourcePort != 67 || r.DestinationPort != 68
                || r.L4Len is < 200 or > 1500
                || !Research706Evidence.PrivatePair(r))
                return NoMatch();
            if (!_responders.Observe(r.Destination!, r.Source!, r.Id, context.TimestampUtc, 2, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2606", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "two_distinct_udp67_responder_sources", "rule"),
                new DetectionEvidenceItem("outcome", "competing_dhcp_responder_datagrams_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Two distinct DHCP-server-port responders targeted one private client within ten seconds; DHCP message type and authorization are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 2,
                windowSeconds: 10);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
