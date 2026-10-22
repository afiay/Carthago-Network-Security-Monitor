// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R210_PypiPackageDownloadFromRareDomainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R210_PypiPackageDownloadFromRareDomainRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R210",
            Name: "PyPI Package Download From Rare Domain",
            Category: "CloudDev",
            Description: "Detects pip or poetry artifact downloads from first-seen non-official Python package hosts instead of any pypi string mention.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R210.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R210",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.Baseline },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The request must look like a Python package artifact or simple-index fetch.",
                "The client should look like pip or poetry.",
                "The host must be external, non-official, and newly observed."
            },
            negativeConditions: new[]
            {
                "Do not alert on pypi.org or files.pythonhosted.org.",
                "Do not alert on generic web downloads by Python processes that do not look like package retrieval."
            },
            minimumConfidence: 76,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host",
            falsePositives: new[] { "Approved internal Python mirrors or sanctioned private package indexes can match this pattern during onboarding." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive pip artifact from rare domain sample", "negative pythonhosted artifact sample" });

        public R210_PypiPackageDownloadFromRareDomainRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!LooksLikePypiArtifactRequest(record) || IsOfficialPackageRegistryHost(host) || !IsExternalAddress(host))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.pypi-host", record.Source ?? "unknown", host, context, "ecosystem=pypi");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen($"{record.Source}:pypi:{host}", context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("matched_conditions", "python_package_request,unofficial_host,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The Python package client fetched package material from a first-seen non-official external host.",
                "Severity is Medium because rare Python package hosts can indicate dependency confusion, typosquatting, or shadow package distribution.",
                "Approved private Python indexes can look similar when first introduced. Validate package source policy before escalating.",
                "Review the package path and Python process involved in the download.",
                "Confirm whether the host is an approved private Python package mirror."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Python package download from first-seen external host observed",
                "PypiRareDomain",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.18, "python-package-request");
                    confidence.AddEvidence(0.18, "unofficial-host");
                    confidence.AddEvidence(0.16, "first-seen");
                },
                cooldownKey: $"{record.Source}:{host}");
        }
    }
}
