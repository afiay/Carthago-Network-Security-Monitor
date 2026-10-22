// SPDX-License-Identifier: MIT
// File: Engine/Rules/CloudSaas/R112_SaaSExportLikeTrafficPatternRule.cs
using System;
using System.Collections.Generic;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.Rules.CloudSaas
{
    public sealed class R112_SaaSExportLikeTrafficPatternRule : CloudSaasPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R112",
            Name: "SaaS Export-Like Traffic Pattern",
            Category: "CloudSaas",
            Description: "Detects SaaS export-like API or workflow traffic when the destination is a business SaaS host and the request contains explicit export semantics plus meaningful transfer context.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R112.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudSaasProfile(
            ruleId: "R112",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri", "saas_or_cloud_host" },
            evidenceFields: new[]
            {
                "cloud.host", "cloud.providerRoot", "http.uri", "flow.bytes", "matched_conditions"
            },
            positiveConditions: new[]
            {
                "The destination must be a recognizable SaaS or cloud-business host.",
                "The request path, headers, or info must explicitly indicate export, archive, backup, takeout, or bulk data movement semantics.",
                "The request must also carry upload-like, automation, repetition, or non-trivial payload context."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic SaaS API use without export semantics.",
                "Do not alert on tiny one-off requests that mention export-like text without transfer context.",
                "Do not alert when the host is not classifiable as SaaS or cloud business traffic."
            },
            minimumConfidence: 78,
            threshold: 2,
            window: TimeSpan.FromMinutes(10),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+provider",
            falsePositives: new[]
            {
                "Approved data-export, compliance, reporting, or backup jobs can legitimately use export-oriented SaaS APIs.",
                "Administrative workflows may invoke bulk export paths during maintenance or tenant migration."
            },
            tuningKnobs: new[] { "Mode", "MinimumPayloadBytes", "RepeatThreshold", "WindowSeconds" },
            requiredTests: new[]
            {
                "positive SaaS export-like sample",
                "negative generic SaaS API sample",
                "negative missing-export-context sample"
            });

        public R112_SaaSExportLikeTrafficPatternRule()
            : base(Rule, Profile)
        {
        }

        protected override string? InvestigationHintOverride
            => "Review whether the request path truly initiates or performs a bulk export, archive, or backup action and whether that operation is approved for the user, tenant, and source process.";

        protected override string? TuningHintOverride
            => "Tune payload and repetition thresholds, but keep explicit export semantics mandatory so routine SaaS API traffic does not become noisy.";

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (string.IsNullOrWhiteSpace(host)
                || !IsInternalAddress(record.Source)
                || !IsExternalAddress(record.Destination)
                || !IsSaasBusinessHost(host))
            {
                return NoMatch();
            }

            if (!HasExportMetadata(record))
                return NoMatch();

            var bytes = TransferBytes(record);
            var minimumPayloadBytes = IntSetting(Descriptor.RuleId, "MinimumPayloadBytes", 300_000, 16_000, 100_000_000);
            var repeatWindow = TimeSpan.FromSeconds(IntSetting(Descriptor.RuleId, "WindowSeconds", 600, 60, 3600));
            var repeatThreshold = IntSetting(Descriptor.RuleId, "RepeatThreshold", 2, 1, 64);
            var repeatCount = CountWindowEvents($"{Descriptor.RuleId}:{record.Source}:{ProviderIdentity(host)}", context.TimestampUtc, repeatWindow);
            var automation = IsLikelyAutomationProcess(record);
            var uploadLike = HasUploadShape(record, minimumPayloadBytes);
            if (!uploadLike && !automation && bytes < minimumPayloadBytes && repeatCount < repeatThreshold)
                return NoMatch();

            if (IsEnterpriseSyncHost(host) && !automation && bytes < minimumPayloadBytes * 2L && repeatCount < repeatThreshold + 1)
                return NoMatch();

            var matchedConditions = new List<string> { "saas_business_host", "explicit_export_semantics" };
            if (uploadLike) matchedConditions.Add("upload_or_large_request_context");
            if (automation) matchedConditions.Add("automation_process");
            if (repeatCount >= repeatThreshold) matchedConditions.Add("repeated_export_calls");

            var provider = ProviderIdentity(host);
            var whyMatched = $"{record.Source} contacted export-oriented SaaS path(s) on {provider} {repeatCount} time(s) within {repeatWindow.TotalMinutes:F0} minutes.";
            var severityReason = "Severity is High because the request combined explicit export semantics with meaningful transfer or automation context against a SaaS business platform.";
            var falsePositives = "Approved compliance, reporting, and backup workflows can use export APIs legitimately. Validate tenant, role, and process ownership before escalating.";

            var evidence = new List<DetectionEvidenceItem>
            {
                new("count", repeatCount.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("window_seconds", ((int)repeatWindow.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule"),
                new("matched_conditions", string.Join(",", matchedConditions), "rule")
            };
            evidence.AddRange(AnalystContext(
                whyMatched,
                severityReason,
                falsePositives,
                "Inspect the SaaS path and request metadata to confirm whether this is an actual export, archive, or backup operation.",
                "Validate whether the user, token, or service account is approved to perform bulk export actions.",
                "Correlate with endpoint and identity telemetry to determine whether the export aligns with expected administrative workflows."));

            return MatchCloud(
                context,
                SeverityLevel.High,
                $"Export-like SaaS traffic observed to {provider}",
                host,
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.32, "explicit-export-semantics");
                    confidence.AddEvidence(0.20, "saas-business-host");
                    if (uploadLike) confidence.AddEvidence(0.12, "upload-or-large-request-context");
                    if (automation) confidence.AddCorrelation(0.14, "automation-process");
                    if (repeatCount >= repeatThreshold) confidence.AddEvidence(0.08, "repeated-export-calls");
                },
                count: repeatCount,
                window: repeatWindow,
                cooldownKey: $"{record.Source}:{provider}");
        }
    }
}
