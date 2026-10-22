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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsOutboundExternal(record) || !IsUploadMethod(record) || !HasBase64BlobInRequest(record, out var sample)) return NoMatch();
            var support = IsLikelyAutomationProcess(record) || HasUploadMetadata(record) || IsUnknownExternalDomain(record, context, TimeSpan.FromHours(24));
            if (!support) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "http_upload,base64_blob,supporting_context")) { new("payload.sample", sample, "payload") };
            evidence.AddRange(AnalystContext("An outbound HTTP upload carried a long base64-like blob with supporting automation/upload/unknown-domain context.", "Severity is High because base64 wrapping is commonly used to move data through JSON or form fields.", "APIs can legitimately send base64 files. Tune approved API hosts and known app clients.", "Inspect the field name and decoded content if available.", "Check whether the source process is expected to upload encoded blobs."));
            return MatchExfiltration(context, SeverityLevel.High, "Base64-like blob in outbound HTTP upload", "Base64HttpPost", evidence, c => { c.AddEvidence(0.28, "base64-blob"); c.AddEvidence(0.22, "external-http-upload"); c.AddEvidence(0.14, "supporting-context"); }, cooldownKey: CooldownIdentity(record, "base64-post"));
        }
    }
}
