// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. workbook.R2811.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R769_LinuxPerlRubyHttpRequestBurstRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R769",
            Name: "Perl/Ruby high-rate cleartext HTTP request burst",
            Category: "EvasionTunnel",
            Description: "perl or ruby is associated with twelve parser-backed cleartext HTTP GET/POST requests to one public peer within ten seconds. Process novelty, response volume, request semantics and command-and-control are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R769.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R769",
            Name = "Perl/Ruby high-rate cleartext HTTP request burst",
            Category = "EvasionTunnel",
            Description = "workbook.R2811: the Linux obfuscated-C2 analytic requires custom/unseen process context and asymmetric response volume. Carthago retains a disjoint interpreter process family plus bounded HTTP request rate only.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "http.method", "http.uri", "process.name", "process.id" },
            EvidenceFields = new[] { "research.identifier", "matched_conditions", "outcome" },
            PositiveConditions = new[]
            {
                "Require coherent typed packet/parser fields and this rule's exact independent predicate.",
                "Process attribution is best-effort local tuple enrichment, not authenticated endpoint process identity.",
                "Stateful candidates accept unique packet IDs in monotonic UTC order inside bounded rule-owned windows."
            },
            NegativeConditions = new[]
            {
                "Reject missing or contradictory transport/parser fields, wrong direction, malformed endpoints and free-form Info-only assertions.",
                "Reject duplicate packet IDs, reverse time, expired windows and cooldown repeats.",
                "Do not infer command lines, approved asset role, credentials, authentication success, C2 control, transfer completion, DoS impact or compromise."
            },
            FalsePositives = new[] { "Web automation, API clients, deployment scripts, monitoring and performance tests written in Perl or Ruby can generate high request rates." },
            MinimumConfidence = 80,
            WindowThreshold = 12,
            Window = TimeSpan.FromSeconds(10),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+perl_or_ruby_pid+public_http_peer+request_burst",
            TuningKnobs = new[] { "Mode", "ApprovedSources", "ApprovedDestinations", "ApprovedProcesses", "ApprovedMaintenanceWindows" },
            RequiredTests = new[]
            {
                "positive shaped case and benign near miss",
                "missing/contradictory telemetry",
                "duplicate ID, reverse-time and expiry for stateful candidates",
                "cooldown suppression and recovery",
                "privacy/redaction, non-convergence, Candidate Shadow and registry uniqueness"
            }
        });

        private readonly WebSignatureCooldown _cooldown = new();
        private readonly Research736CountWindow _window = new();

        public R769_LinuxPerlRubyHttpRequestBurstRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!Research766Evidence.LinuxInterpreterWebProcess(r)
                || !Research766Evidence.CleartextHttpRequest(r, out var size)
                || !_window.Observe(r.Source + "|" + r.Destination + "|" + r.DestinationPort + "|" + r.ProcessId,
                    r.Id, size, context.TimestampUtc, 12, 10))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R2811", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "perl_ruby_cleartext_http_request_burst", "rule"),
                new DetectionEvidenceItem("outcome", "request_rate_only_process_novelty_and_c2_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Perl/Ruby cleartext HTTP request burst observed; process novelty, response asymmetry and command-and-control semantics are unknown.",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.43, "typed-producer-evidence");
                    confidence.AddEvidence(0.35, "specific-workbook-predicate");
                    confidence.AddCorrelation(0.12, "bounded-independent-correlation");
                },
                count: 12,
                windowSeconds: 10);

            return RuleEvaluationResult.Match(Descriptor.RuleId, evt);
        }
    }
}
