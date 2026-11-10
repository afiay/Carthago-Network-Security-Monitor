// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. xUnit source authored first; zero tests/builds executed. workbook.R1019.
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R868_SplitScopeSameNameAReplyRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R868", Name: "Same DNS name receives private then public A answer across clients", Category: "DnsThreat",
            Description: "Same private resolver answers one internal name with a private IPv4 and then a public IPv4 to a different client within 90s; split-horizon policy or unauthorized edits remain unknown.",
            DefaultSeverity: SeverityLevel.Medium, ConfigKey: "Rules.R868.Enabled",
            EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R868", Name = "Same DNS name receives private then public A answer across clients", Category = "DnsThreat",
            Description = "workbook.R1019: Same private resolver answers one internal name with a private IPv4 and then a public IPv4 to a different client within 90s; split-horizon policy or unauthorized edits remain unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns },
            RequiredFields = new[] { "dns.qname", "dns.answers", "source", "destination", "packet.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Coherent typed IPv4 transport fields and independent packet-observable predicate.",
                "Per-rule bounded monotonic UTC correlation; no missing producer claimed."
            },
            NegativeConditions = new[]
            {
                "Missing or contradictory fields, duplicate IDs, reversed time and expired windows fail closed.",
                "No trusted identity, host audit, changed configuration, authenticated action, exploit, C2 or impact inferred."
            },
            FalsePositives = new[]
            {
                "Authorized network administration, service discovery, maintenance and diagnostics may generate this shape."
            },
            MinimumConfidence = 80, WindowThreshold = 2,
            Window = TimeSpan.FromSeconds(90), Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "same_name_private_then_public_dns_answer_distinct_clients",
            TuningKnobs = new[] { "Mode", "ApprovedPeers", "ApprovedAssetRoles", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "positive and benign typed cases", "missing and contradictory fields",
                "duplicate IDs, reverse time, window expiry", "cooldown recovery",
                "raw Info exclusion", "neighbor independence", "Candidate Shadow registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly SplitScopeReplyWindow _split = new();
        public R868_SplitScopeSameNameAReplyRule() : base(Rule, Profile) { }

        // Per-rule, instance-owned evidence; never store DNS payloads or trust the resolver identity.
        private sealed class SplitScopeReplyWindow
        {
            private sealed class Slot
            {
                internal string Client = string.Empty;
                internal Guid Id;
                internal DateTime First, Last;
                internal bool Public;
            }
            private readonly object _gate = new();
            private readonly Dictionary<string, Slot> _slots = new(StringComparer.Ordinal);

            internal bool Observe(string key, string client, Guid id, DateTime at, bool isPublic)
            {
                if (string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(client)
                    || id == Guid.Empty || at.Kind != DateTimeKind.Utc) return false;
                lock (_gate)
                {
                    if (_slots.TryGetValue(key, out var prior))
                    {
                        if (at <= prior.Last || id == prior.Id) return false;
                        if (at - prior.First <= TimeSpan.FromSeconds(90) && !prior.Public
                            && isPublic && !string.Equals(prior.Client, client, StringComparison.Ordinal))
                        { _slots.Remove(key); return true; }
                        if (at - prior.First <= TimeSpan.FromSeconds(90))
                        { prior.Last = at; return false; }
                    }
                    if (_slots.Count >= 512 && !_slots.ContainsKey(key))
                    {
                        foreach (var stale in _slots.Where(x => at >= x.Value.Last
                            && at - x.Value.Last > TimeSpan.FromMinutes(5)).Select(x => x.Key).ToArray())
                            _slots.Remove(stale);
                        if (_slots.Count >= 512) return false;
                    }
                    _slots[key] = new Slot { Client = client, Id = id, First = at, Last = at, Public = isPublic };
                    return false;
                }
            }
        }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.UdpData(r) || !Research786NetworkEvidence.Internal(r)
                || r.SourcePort != 53 || !r.DnsIsResponse
                || !string.Equals(r.ApplicationProtocol, "DNS", StringComparison.OrdinalIgnoreCase)
                || !string.Equals(r.DnsQtype, "A", StringComparison.OrdinalIgnoreCase)
                || string.IsNullOrWhiteSpace(r.DnsQname) || r.DnsQname.Length > 253
                || r.DnsTtl is < 1 or > 86400 || r.HttpMethod != null || r.HttpUri != null
                || r.Sni != null || r.TlsVersion != null
                || !IPAddress.TryParse(r.DnsAnswers, out var answer)
                || answer.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork
                || (!Research646Evidence.Private(answer) && !Research646Evidence.Public(answer)))
                return NoMatch();
            var key = r.Source! + "|" + r.DnsQname.TrimEnd('.').ToLowerInvariant();
            if (!_split.Observe(key, r.Destination!, r.Id, context.TimestampUtc,
                Research646Evidence.Public(answer))) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1019", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "same_name_private_then_public_dns_answer_distinct_clients", "rule"),
                new DetectionEvidenceItem("outcome", "typed_packet_shape_only_causality_and_impact_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Same DNS name receives private then public A answer across clients; producer provenance, authorization and security outcome unverified.",
                evidence, confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "independent_owner_workbook_predicate");
                    confidence.AddCorrelation(0.12, "bounded_monotonic_utc_observation");
                }, count: 2, windowSeconds: 90);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}

