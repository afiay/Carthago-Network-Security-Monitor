// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED; xUnit authored, zero executed. Workbook R1304.
using System;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R717_ScriptProcessCodeRepositoryApiPostRule : EvidenceDrivenPrecisionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R717",
            Name: "Script or curl process POST to GitHub/GitLab repository API",
            Category: "CloudDev",
            Description: "A PowerShell, curl, or Python process is associated with a cleartext outbound HTTP POST to a GitHub or GitLab repository API route. File reads, request-body contents, authentication, accepted upload, repository modification, and exfiltration are not observed.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R717.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateEvidenceDrivenProfile(new PrecisionRuleSpec
        {
            RuleId = "R717",
            Name = "Script or curl process POST to GitHub/GitLab repository API",
            Category = "CloudDev",
            Description = "Workbook R1304: the workbook source correlates sensitive file reads with HTTPS POST uploads. Carthago cannot see those file reads or encrypted request bodies, so this rule is limited to exact process attribution plus a parsed cleartext repository-API POST, excluding Git smart-HTTP push and Gist-specific behavior.",
            Severity = SeverityLevel.Medium,
            Maturity = RulePrecisionMaturity.Candidate,
            RuntimeMode = RuleRuntimeMode.Shadow,
            RequiredTelemetry = new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Process },
            RequiredFields = new[] { "source", "destination", "http.method", "http.host", "http.uri", "process.name", "process.id" },
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
            FalsePositives = new[] { "Developer automation, release engineering, repository maintenance, CI/CD tooling, and approved administrative scripts can legitimately POST to repository APIs." },
            MinimumConfidence = 82,
            WindowThreshold = 1,
            Window = TimeSpan.FromSeconds(300),
            Cooldown = TimeSpan.FromMinutes(10),
            DistinctBy = "source+process+repository_api_host",
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

        public R717_ScriptProcessCodeRepositoryApiPostRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!WebSignatureRequestEvidence.TryGet(r, out var method, out var uri)
                || method != "POST"
                || !Research676Evidence.PrivateToPublic(r)
                || !Research716Evidence.Process(r, "powershell.exe", "pwsh.exe", "curl.exe", "curl", "python.exe", "python")
                || !Research716Evidence.CodeRepositoryApi(r.HttpHost, uri))
                return NoMatch();

            var state = _cooldown.Observe(r.Source!, r.Destination!, r.Id, context.TimestampUtc);
            if (state == WebSignatureObservation.None) return NoMatch();
            if (state == WebSignatureObservation.Suppressed)
                return RuleEvaluationResult.SuppressedMatch(Descriptor.RuleId);

            var evidence = new[]
            {
                new DetectionEvidenceItem("research.identifier", "workbook.R1304", "owner-research"),
                new DetectionEvidenceItem("matched_conditions", "script_process_repository_api_post", "rule"),
                new DetectionEvidenceItem("outcome", "repository_api_post_request_only_unknown", "rule")
            };

            var evt = CreateDetectionEvent(
                context,
                SeverityLevel.Medium,
                "Script/curl process-associated repository API POST observed; file source, authentication, upload result, and exfiltration are unknown.",
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
