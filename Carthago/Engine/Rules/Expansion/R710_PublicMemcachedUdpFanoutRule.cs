// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1114.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R710_PublicMemcachedUdpFanoutRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R710",
            Name: "Private host UDP/11211 fanout to three public peers",
            Category: "IotOtAdvanced",
            Description: "One private source sends coherent UDP datagrams to Memcached port 11211 on three distinct public peers within 60 seconds. This is an amplification-shaped fanout only; source spoofing, Memcached command semantics, reflection, victim traffic, and denial-of-service impact are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R710.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R710",
            Name = "Private host UDP/11211 fanout to three public peers",
            Category = "IotOtAdvanced",
            Description = "Workbook R1114: the workbook expects spoofed UDP requests and output/input ratios. Carthago cannot establish spoofing or amplification ratios, so this independent candidate is limited to distinct public UDP/11211 fanout and is separate from R242 NTP amplification and R439 Memcached enumeration.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "udp", "destination.port", "l4.length" },
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
            FalsePositives = new[] { "Distributed cache testing, Internet-wide research, vulnerability scanning, and misconfigured clients can contact multiple public Memcached endpoints." },
            MinimumConfidence = 80,
            WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(60),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "private_source+three_public_memcached_peers",
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
        private readonly Research706DistinctWindow _fanout = new();

        public R710_PublicMemcachedUdpFanoutRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research706Evidence.Udp(r)
                || !Research706Evidence.PrivateToPublic(r)
                || r.DestinationPort != 11211 || r.SourcePort is <= 1024
                || r.L4Len is < 8 or > 1400
                || (r.ApplicationProtocol != null && !r.ApplicationProtocol.Equals("memcached", StringComparison.OrdinalIgnoreCase)))
                return NoMatch();
            if (!_fanout.Observe(r.Source + "|11211", r.Destination!, r.Id, context.TimestampUtc, 3, 60))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1114", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "udp11211_three_public_peer_fanout", "rule"),
                new DetectionEvidenceItem("outcome", "memcached_amplification_shaped_fanout_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Private host contacted three public UDP/11211 peers within one minute; amplification, spoofing, and DoS impact are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 3,
                windowSeconds: 60);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
