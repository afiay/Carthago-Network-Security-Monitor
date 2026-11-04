// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R2664.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R723_ScriptProcessDirectExternalHighEntropyDnsRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R723",
            Name: "Script process direct external high-entropy DNS query",
            Category: "DnsAdvanced",
            Description: "A script/interpreter process is associated with a direct query to a public DNS destination where the first label is long and high-diversity. Resolver policy, tunneling semantics, payload encoding, C2, and process command line are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R723.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R723",
            Name = "Script process direct external high-entropy DNS query",
            Category = "DnsAdvanced",
            Description = "Workbook R2664: the Windows DNS-misuse analytic requires resolver-policy violation plus suspicious query/process/destination evidence. This candidate preserves those observable components: direct external resolver use, exact script process attribution, and a bounded high-entropy label shape.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Dns, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "dns.qname", "dns.qtype", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet, parser, and best-effort process fields for this exact independent predicate.",
                "Multi-observation rules use bounded unique packet IDs with UTC ordering and a fixed rule-owned window.",
                "Only the observable network/request/process association is claimed; endpoint or server outcome is not inferred."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, and free-form Info-only indicators.",
                "Reject duplicate packet IDs, stale/out-of-order observations, and cooldown repeats.",
                "Do not infer authentication, command-line arguments, file reads/writes, transfer completion, exploit success, or compromise."
            },
            FalsePositives = new[] { "Developer tooling, package managers, telemetry SDKs, anti-abuse systems, and validation workflows can generate long high-diversity DNS labels from script processes." },
            MinimumConfidence = 83,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+script_pid+external_resolver+high_entropy_label",
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

        public R723_ScriptProcessDirectExternalHighEntropyDnsRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!DnsSignatureRequestEvidence.TryGetQuery(r, out var query)
                || r.DestinationPort != 53
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.Process(r, "powershell.exe", "pwsh.exe", "python.exe", "python", "wscript.exe", "cscript.exe", "mshta.exe")
                || !Research716Evidence.HighEntropyDnsQuery(query))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2664", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "script_process_direct_external_high_entropy_dns", "rule"),
                new DetectionEvidenceItem("outcome", "dns_misuse_shape_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Script-process direct external high-entropy DNS query observed; tunneling, C2, resolver-policy authorization, and payload meaning are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 1,
                windowSeconds: 300);
            DnsSignatureRequestEvidence.RedactQuery(evt, query);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
