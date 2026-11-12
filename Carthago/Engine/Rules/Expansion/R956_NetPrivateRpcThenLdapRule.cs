// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Original workbook R2074; xUnit source authored first.
using System;
using Carthago.Models;
namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R956_NetPrivateRpcThenLdapRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R956", Name: "Net utility private RPC then same-peer LDAP SYN", Category: "Discovery",
            Description: "Same net/net1 PID sends TCP/135 then TCP/389 SYN to one private peer. Enumeration command, returned system/user data and authorization are unknown.", DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R956.Enabled", EnabledByDefault: true);
        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R956", Name = "Net utility private RPC then same-peer LDAP SYN", Category = "Discovery",
            Description = "workbook.R2074: Same net/net1 PID sends TCP/135 then TCP/389 SYN to one private peer. Enumeration command, returned system/user data and authorization are unknown.", Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate, RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "source.port", "destination.port", "packet.id", "process.id", "process.name" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[] { "Same net/net1 PID sends TCP/135 then TCP/389 SYN to one private peer. Enumeration command, returned system/user data and authorization are unknown.", "Coherent typed IPv4 fields and independent bounded UTC observations." },
            NegativeConditions = new[] { "Wrong endpoints, missing or contradictory typed evidence, duplicate IDs, reverse UTC or expired windows fail closed.",
                "No unsupported host action, authenticated session, authorization or security outcome inferred." },
            FalsePositives = new[] { "Authorized administration, maintenance, deployment and diagnostics may share the observable shape." },
            MinimumConfidence = 80, WindowThreshold = 2, Window = TimeSpan.FromSeconds(45),
            Cooldown = TimeSpan.FromMinutes(10), DistinctBy = "R956_NetPrivateRpcThenLdapRule",
            TuningKnobs = new[] { "Mode", "ApprovedProcesses", "ApprovedDestinations", "ApprovedMaintenanceWindows" },
            RequiredTests = new[] { "typed positive and benign near miss", "missing and contradictory fields", "duplicate and reverse UTC", "correlation expiry and isolation", "cooldown recovery", "raw Info excluded", "independent state and registry" }
        });
        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research786TwoStageWindow _stages = new();
        public R956_NetPrivateRpcThenLdapRule() : base(Rule, Profile) { }
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research786NetworkEvidence.Coherent(r)) return NoMatch();
            var first = Research786NetworkEvidence.Internal(r) && Research676Evidence.Syn(r) && r.DestinationPort == 135 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && r.Source != r.Destination && Research676Evidence.Process(r, "net.exe", "net", "net1.exe", "net1");
            var second = Research786NetworkEvidence.Internal(r) && Research676Evidence.Syn(r) && r.DestinationPort == 389 && r.Sni == null && r.HttpUri == null && !r.DnsIsResponse && r.Source != r.Destination && Research676Evidence.Process(r, "net.exe", "net", "net1.exe", "net1");
            if (!first && !second) return NoMatch();
            var key = r.Source! + "|" + r.Destination! + "|" + r.ProcessId;
            if (!_stages.Observe(key, r.Id, context.TimestampUtc, first, 45)) return NoMatch();
            var status = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (status == WebSignatureObservation.None) return NoMatch();
            if (status == WebSignatureObservation.Suppressed) return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);
            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2074", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "R956_NetPrivateRpcThenLdapRule", "rule"),
                new DetectionEvidenceItem("outcome", "typed_observation_only_authorization_and_outcome_unknown", "rule")
            };
            var evt = CreateDetectionEvent(context, SeverityLevel.Medium,
                "Net utility private RPC then same-peer LDAP SYN observed; authorization, causality and outcome remain unverified.", evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.45, "coherent_typed_packet_fields");
                    confidence.AddEvidence(0.33, "specific_workbook_observable_projection");
                    confidence.AddCorrelation(0.12, "bounded_utc_observation");
                }, count: 2, windowSeconds: 45);
            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
