// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R177_HighRiskFileUploadExtensionRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R177_HighRiskFileUploadExtensionRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R177",
            Name: "High-Risk File Upload Extension",
            Category: "HttpApi",
            Description: "Detects HTTP upload workflows carrying executable or web-shell style filenames instead of every multipart request.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R177.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R177",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "upload.filename", "http.path" },
            positiveConditions: new[]
            {
                "The request must have concrete upload semantics such as multipart/form-data or an upload-like path.",
                "The filename or upload target must end in an executable or server-side extension such as .jsp or .php.",
                "Ordinary image and document uploads should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on benign media or document uploads.",
                "Do not alert on multipart traffic when no high-risk filename is present."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+filename",
            falsePositives: new[]
            {
                "Application deployment pipelines or sanctioned content management workflows may upload executable archives intentionally."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive high-risk upload filename sample",
                "negative benign image upload sample"
            });

        public R177_HighRiskFileUploadExtensionRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !TryGetHighRiskUploadName(record, out var fileName))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "upload_context,high_risk_extension", "rule"),
                new("upload.filename", fileName, "http"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "An HTTP upload workflow carried a filename with a high-risk executable or web-shell style extension.",
                "Severity is High because server-side executable uploads often indicate attempted web-shell placement or unauthorized deployment.",
                "Deployment pipelines and some content management systems can legitimately upload executable archives or application artifacts.",
                "Confirm whether the target endpoint is expected to receive deployable code or server-side templates from this source.",
                "Review adjacent admin login, WebDAV, request smuggling, or .git/.env probe activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "High-risk upload filename observed",
                "HighRiskUpload",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "upload-context");
                    confidence.AddEvidence(0.30, "high-risk-extension");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{fileName}");
        }
    }
}
