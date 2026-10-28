// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R253_Base64BlobInHttpPostRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R253_Base64BlobInHttpPostRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R253", "Base64 Blob In HTTP POST", "ExfiltrationAdvanced", "Detects large base64-like blobs in outbound HTTP upload requests with automation or external unknown-destination support.", SeverityLevel.High, "Rules.R253.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R253", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload, RuleTelemetryKind.Process }, new[] { "source", "external_destination", "http_post", "base64_blob" }, new[] { "http.path", "payload.sample", "matched_conditions" }, new[] { "Request must be POST/PUT/PATCH to an external target.", "Payload/URI/header text must include a long base64-like blob.", "Automation process, unknown domain, or upload metadata must support exfil intent." }, new[] { "Do not alert on OAuth/JWT tokens alone.", "Do not alert on ordinary browser forms without long blob evidence." }, 82, 1, TimeSpan.FromMinutes(10), TimeSpan.FromMinutes(30), "source+destination+base64", new[] { "Some APIs legitimately transfer base64-encoded documents or images." }, new[] { "Mode", "BlobLength", "ApprovedApiHosts", "CooldownSeconds" }, new[] { "positive base64 POST exfil sample", "negative JWT-only auth sample" });
        public R253_Base64BlobInHttpPostRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch251255Evidence.EncodedQuery(record)
                || IsLikelyApprovedSyncOrBackup(record)
                || !IsLikelyAutomationProcess(record)
                || !_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "parsed_http_upload,base64_query_parameter,automation_process", "rule"),
                new("http.payload_visibility", "query_only_no_request_body", "rule")
            };
            evidence.AddRange(AnalystContext("An automated cleartext HTTP upload request carried an encoded query parameter.",
                "The request body is not captured or decoded; this does not prove an encoded POST body or exfiltration.",
                "Legitimate APIs may use encoded query values.",
                "Corroborate endpoint context and request-body evidence."));
            return MatchExfiltration(context, SeverityLevel.High,
                "Base64-like query on HTTP upload request", "Base64HttpPost", evidence,
                c => { c.AddEvidence(0.28, "encoded-query"); c.AddEvidence(0.22, "external-http-upload"); c.AddEvidence(0.14, "automation-process"); },
                cooldownKey: record.Source + ":" + record.Destination + ":encoded-query");

        }
    }
}
