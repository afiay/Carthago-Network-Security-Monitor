// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook workbook.R2663.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R727_LinuxScriptProcessDirectExternalDotRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R727",
            Name: "Linux script process direct external DNS-over-TLS contact",
            Category: "DnsAdvanced",
            Description: "A scripting or shell process is associated with direct outbound TLS/853 to a public peer. Resolver policy, asset role, DNS payload, DoT authorization, tunneling, C2 and query contents are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R727.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R727",
            Name = "Linux script process direct external DNS-over-TLS contact",
            Category = "DnsAdvanced",
            Description = "workbook.R2663: the workbook analytic combines resolver-policy bypass with native DNS/DoH/DoT and process evidence. This candidate narrows it to exact script/shell process attribution and direct external DoT transport only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Tls, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "destination.port", "tls.sni", "tls.version", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet fields plus the exact process/network predicate defined by this independent candidate.",
                "Correlated rules accept only unique packet IDs in monotonic UTC order inside a bounded rule-owned window.",
                "Only the observed process association, network shape, request classification or packet burst is asserted."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, invalid endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command-line arguments, asset role, file access, successful transfer, authenticated endpoint state, C2, DoS impact, exploit success or compromise."
            },
            FalsePositives = new[] { "Approved resolvers, diagnostic scripts, privacy tools, package tooling, security products and engineering workstations may intentionally use external DNS-over-TLS." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+script_process+external_dot_peer",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive real-life-shaped sample and benign near miss",
                "missing and contradictory telemetry",
                "duplicate ID, reverse time and window expiry for correlated candidates",
                "cooldown suppression and recovery",
                "fixed evidence privacy, Candidate Shadow and unique registry"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();

        public R727_LinuxScriptProcessDirectExternalDotRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research726Evidence.Dot853(r)
                || !Research726Evidence.LinuxDnsTool(r))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2663", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "linux_script_process_direct_external_dot", "rule"),
                new DetectionEvidenceItem("outcome", "dot_transport_contact_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Script/shell process direct external DNS-over-TLS contact observed; resolver policy, DNS content, tunneling and C2 are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
