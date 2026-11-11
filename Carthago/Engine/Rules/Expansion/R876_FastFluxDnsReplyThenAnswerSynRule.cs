// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R2785.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R876_FastFluxDnsReplyThenAnswerSynRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R876", Name: "Three low-TTL DNS answers then SYN to latest public answer", Category: "DnsThreat",
            Description: "Same private resolver gives three distinct low-TTL public A answers for one name to one private client, then the client SYNs to the last address; neither malicious fast-flux control nor process lineage is established.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R876.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R876", Name = "Three low-TTL DNS answers then SYN to latest public answer", Category = "DnsThreat",
            Description = "workbook.R2785: Same private resolver gives three distinct low-TTL public A answers for one name to one private client, then the client SYNs to the last address; neither malicious fast-flux control nor process lineage is established.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "dns.qname", "dns.answers", "dns.ttl", "source", "destination", "tcp.flags", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent observable source predicate.",
                "Bounded per-rule monotonic UTC observation, with no unavailable producer asserted."
            },
            NegativeConditions = new[]
            {
                "Missing, contradictory, duplicate, out-of-order or expired evidence fails closed.",
                "No authenticated identity, file transfer, decoded encrypted content, command execution, configuration or outcome inferred."
            },
            FalsePositives = new[]
            {
                "Approved maintenance, software deployment, diagnostics, administrative sessions and normal traffic may share this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 4,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "same_resolver_three_low_ttl_public_a_then_last_answer_syn",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedProcesses", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near-miss cases",
                "missing or contradictory transport", "duplicate and reverse UTC / expired window",
                "cooldown recovery", "raw Info exclusion", "neighbor independence",
                "unique Candidate Shadow registration" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly FastFluxReplyWindow _answers = new();
        public R876_FastFluxDnsReplyThenAnswerSynRule() : base(Rule, Profile) { }

        // Only single public IPv4 A answers are admitted. Never infer resolver policy or DNS compromise.
        private sealed class FastFluxReplyWindow
        {
            private sealed class Slot
            {
                internal string Client = string.Empty;
                internal string LatestAddress = string.Empty;
                internal DateTime First, Last;
                internal readonly HashSet<Guid> Ids = new();
                internal readonly HashSet<string> Answers = new(StringComparer.Ordinal);
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

            internal void ObserveReply(string client, string resolver, string name, string address,
                Guid id, DateTime at)
            {
                if (client.Length == 0 || resolver.Length == 0 || name.Length == 0 || id == Guid.Empty
                    || at.Kind != DateTimeKind.Utc) return;
                var key = client + "|" + resolver + "|" + name;
                lock (_gate)
                {
                    if (!_slots.TryGetValue(key, out var state))
                    {
                        if (_slots.Count >= 512)
                        {
                            foreach (var old in _slots.Where(x => at >= x.Value.Last
                                && at - x.Value.Last > TimeSpan.FromMinutes(5)).Select(x => x.Key).ToArray())
                                _slots.Remove(old);
                            if (_slots.Count >= 512) return;
                        }
                        state = new Slot { Client = client, First = at };
                        _slots.Add(key, state);
                    }
                    if (at <= state.Last || state.Ids.Contains(id)) return;
                    if (at - state.First > TimeSpan.FromSeconds(90))
                    {
                        state.First = at;
                        state.Ids.Clear();
                        state.Answers.Clear();
                    }
                    if (state.Ids.Count >= 64) return;
                    state.Ids.Add(id);
                    state.Answers.Add(address);
                    state.LatestAddress = address;
                    state.Last = at;
                }
            }

            internal bool ObserveSyn(string client, string address, Guid id, DateTime at)
            {
                if (client.Length == 0 || address.Length == 0 || id == Guid.Empty
                    || at.Kind != DateTimeKind.Utc) return false;
                lock (_gate)
                {
                    foreach (var pair in _slots.ToArray())
                    {
                        var state = pair.Value;
                        if (!string.Equals(state.Client, client, StringComparison.Ordinal)
                            || at <= state.Last || at - state.First > TimeSpan.FromSeconds(90)
                            || state.Ids.Contains(id) || state.Answers.Count < 3
                            || !string.Equals(state.LatestAddress, address, StringComparison.Ordinal))
                            continue;
                        _slots.Remove(pair.Key);
                        return true;
                    }
                    return false;
                }
            }
        }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (Research786NetworkEvidence.UdpData(r) && Research786NetworkEvidence.Internal(r)
                && r.SourcePort == 53 && r.DnsIsResponse
                && string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                && string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                && !string.IsNullOrWhiteSpace(r.DnsQname) && r.DnsQname.Length <= 253
                && r.DnsTtl is >= 1 and <= 30 && r.HttpMethod == null && r.HttpUri == null
                && r.TlsVersion == null && r.Sni == null
                && IPAddress.TryParse(r.DnsAnswers, out var answer) && Research646Evidence.Public(answer))
            {
                _answers.ObserveReply(r.Destination!, r.Source!, r.DnsQname.TrimEnd('.').ToLowerInvariant(),
                    answer.ToString(), r.Id, context.TimestampUtc);
                return NoMatch();
            }
            if (!Research786NetworkEvidence.Coherent(r) || !Research676Evidence.Syn(r)
                || !Research786NetworkEvidence.PrivatePublic(r) || r.DestinationPort != 443
                || !_answers.ObserveSyn(r.Source!, r.Destination!, r.Id, context.TimestampUtc))
                return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2785", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "same_resolver_three_low_ttl_public_a_then_last_answer_syn", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_authorization_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Three low-TTL DNS answers then SYN to latest public answer; producer provenance, authorization, causality and outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 4, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

