// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; 0 tests/builds executed. workbook.R1015.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R837_ConflictingResolverAnswerThenSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R837", Name: "Conflicting public resolver A answers then selected-IP SYN",
            Category: "CommandControl",
            Description: "Two different public resolver IPs send different single public A answers for one qname to one client; that client SYNs to second answer within 60s. No resolver trust or poison proven.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R837.Enabled", EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R837", Name = "Conflicting public resolver A answers then selected-IP SYN",
            Category = "CommandControl",
            Description = "workbook.R1015: Public resolver discrepancy and selected-address SYN; no authenticated DNS trust, cache poisoning or compromise proven.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow },
            RequiredFields = new[] { "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] {
                "Two typed UDP/53 A responses from distinct public resolvers to one client carry different single public IPv4 answers for the same qname.",
                "The client subsequently initiates a typed TCP SYN to the second answer inside a 60-second monotonic UTC window."
            },
            NegativeConditions = new[] {
                "Missing/contradictory DNS fields, multiple answers in one packet, duplicate packet IDs, stale/reversed timestamps fail closed.",
                "No authenticated resolver trust, DNS cache write, endpoint DNS selection or poisoning assumed."
            },
            FalsePositives = new[] { "Geo-DNS, CDN balancing and authorized resolver diversity produce benign discrepancies." },
            MinimumConfidence = 80, WindowThreshold = 3,
            Window = TimeSpan.FromSeconds(60), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "distinct_public_resolver_disagreement_then_second_answer_syn",
            TuningKnobs = new[] { "Mode", "ApprovedResolvers", "ApprovedDestinations" },
            RequiredTests = new[] {
                "response disagreement then selected-IP SYN", "same resolver/answer rejected",
                "reversed/duplicate/expired", "cooldown recovery", "raw Info excluded", "Candidate Shadow registration"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly DisagreementWindow _answers = new();
        public R837_ConflictingResolverAnswerThenSynRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.UdpData(r) && Research786NetworkEvidence.PublicPrivate(r)
                && r.SourcePort == 53 && r.DnsIsResponse
                && string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253
                && r.DnsTtl is > 0 and <= 86400 && r.HttpMethod == null && r.HttpUri == null
                && r.TlsVersion == null && r.Sni == null
                && IPAddress.TryParse(r.DnsAnswers, out var answer) && Research646Evidence.Public(answer))
            {
                _answers.ObserveReply(r.Destination!, r.DnsQname.ToLowerInvariant(), r.Source!,
                    answer.ToString(), r.Id, context.TimestampUtc);
                return NoMatch();
            }

            if (!Research676Evidence.Syn(r) || !Research786NetworkEvidence.PrivatePublic(r)
                || !_answers.ObserveSyn(r.Source!, r.Destination!, r.Id, context.TimestampUtc))
                return NoMatch();

            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[] {
                new DetectionEvidenceItem("research.identifier", "workbook.R1015", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "public_resolver_a_disagreement_then_second_answer_syn", "rule"),
                new DetectionEvidenceItem("outcome", "resolver_trust_dns_poisoning_and_connection_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Different DNS resolver A answers followed by client SYN to the later address observed; no DNS poisoning asserted.",
                evidence, confidence => {
                    confidence.AddEvidence(0.45, "typed_dns_responses_and_tcp_syn");
                    confidence.AddEvidence(0.33, "distinct_resolvers_and_single_public_ipv4_answers");
                    confidence.AddCorrelation(0.12, "same_client_and_qname_bounded_utc");
                }, count: 3, windowSeconds: 60);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }

        // An independent bounded rule-specific state machine, not a shared/converged detector.
        private sealed class DisagreementWindow
        {
            private sealed class Slot
            {
                internal string FirstResolver = string.Empty;
                internal string FirstAnswer = string.Empty;
                internal string SecondAnswer = string.Empty;
                internal DateTime First;
                internal DateTime Latest = DateTime.MinValue;
                internal readonly HashSet<Guid> PacketIds = new();
            }

            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

            internal void ObserveReply(string client, string qname, string resolver, string answer, Guid id, DateTime at)
            {
                if (string.IsNullOrWhiteSpace(client) || string.IsNullOrWhiteSpace(qname)
                    || id == Guid.Empty || at.Kind != DateTimeKind.Utc) return;
                var key = client + "|" + qname;
                lock (_gate)
                {
                    if (!_slots.TryGetValue(key, out var slot))
                    {
                        if (_slots.Count >= 512)
                        {
                            foreach (var stale in _slots.Where(x => at >= x.Value.Latest
                                && at - x.Value.Latest > TimeSpan.FromMinutes(5)).Select(x => x.Key).ToArray())
                                _slots.Remove(stale);
                            if (_slots.Count >= 512) return;
                        }
                        slot = new Slot();
                        _slots.Add(key, slot);
                    }
                    if (at <= slot.Latest || slot.PacketIds.Contains(id)) return;
                    if (slot.PacketIds.Count == 0 || at - slot.First > TimeSpan.FromSeconds(60))
                    {
                        slot.FirstResolver = resolver; slot.FirstAnswer = answer;
                        slot.SecondAnswer = string.Empty; slot.First = at; slot.PacketIds.Clear();
                    }
                    else if (slot.PacketIds.Count < 16 && slot.SecondAnswer.Length == 0
                        && !string.Equals(resolver, slot.FirstResolver, StringComparison.Ordinal)
                        && !string.Equals(answer, slot.FirstAnswer, StringComparison.Ordinal))
                        slot.SecondAnswer = answer;
                    slot.Latest = at;
                    if (slot.PacketIds.Count < 16) slot.PacketIds.Add(id);
                }
            }

            internal bool ObserveSyn(string client, string target, Guid id, DateTime at)
            {
                if (string.IsNullOrWhiteSpace(client) || string.IsNullOrWhiteSpace(target)
                    || id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
                lock (_gate)
                {
                    foreach (var item in _slots)
                    {
                        var slot = item.Value;
                        if (!item.Key.StartsWith(client + "|", StringComparison.Ordinal)
                            || slot.SecondAnswer.Length == 0 || slot.PacketIds.Contains(id)
                            || !string.Equals(slot.SecondAnswer, target, StringComparison.Ordinal)
                            || at <= slot.Latest || at - slot.First > TimeSpan.FromSeconds(60)) continue;
                        slot.Latest = at;
                        slot.SecondAnswer = string.Empty;
                        slot.PacketIds.Add(id);
                        return true;
                    }
                    return false;
                }
            }
        }
    }
}
