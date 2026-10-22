// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R208_PackageManagerToSuspiciousRegistryRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R208_PackageManagerToSuspiciousRegistryRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R208",
            Name: "Package Manager To Suspicious Registry",
            Category: "CloudDev",
            Description: "Detects package-manager traffic to first-seen non-official external registry hosts instead of matching generic registry words.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R208.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R208",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.DevOpsAudit, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "http.path", "baseline.reason", "matched_conditions" },
            positiveConditions: new[]
            {
                "The traffic must look like a concrete package-manager registry request.",
                "The host must be external and not one of the official registry providers for the ecosystem.",
                "The registry host should be newly observed."
            },
            negativeConditions: new[]
            {
                "Do not alert on official package registries.",
                "Do not alert on generic HTTP traffic that merely contains the word registry."
            },
            minimumConfidence: 76,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(30),
            distinctBy: "source+host",
            falsePositives: new[] { "Newly introduced enterprise registries or sanctioned third-party artifact mirrors can legitimately match this pattern." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive package manager to custom registry sample", "negative official npm registry sample" });

        public R208_PackageManagerToSuspiciousRegistryRule() : base(Rule, Profile) { }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            var host = BestHost(record);
            if (!TryClassifyPackageRegistryRequest(record, out var ecosystem) || IsOfficialPackageRegistryHost(host))
                return NoMatch();

            var baseline = ObserveBaseline("clouddev.package-registry-host", record.Source ?? "unknown", host, context, $"ecosystem={ecosystem}");
            var firstSeen = baseline.IsFirstSeen || FirstTimeSeen($"{record.Source}:pkg:{host}", context.TimestampUtc);
            if (!firstSeen)
                return NoMatch();

            var evidence = new List<DetectionEvidenceItem>
            {
                new("baseline.reason", baseline.Reason, "baseline"),
                new("cloud.ecosystem", ecosystem, "cloud"),
                new("matched_conditions", "package_manager_registry_request,unofficial_registry,first_seen", "rule")
            };
            evidence.AddRange(AnalystContext(
                "The source contacted a first-seen non-official external package registry using concrete package-manager semantics.",
                "Severity is Medium because unfamiliar registries can indicate dependency confusion, shadow artifacts, or supply-chain bypass.",
                "Enterprise artifact mirrors and sanctioned third-party registries can look similar. Validate registry ownership and package-manager policy before escalating.",
                "Review the package manager process and package path involved in the request.",
                "Confirm whether the registry host is approved for the ecosystem."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Package manager request to first-seen external registry observed",
                "SuspiciousPackageRegistry",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "package-manager-registry-request");
                    confidence.AddEvidence(0.18, "unofficial-registry");
                    confidence.AddEvidence(0.16, "first-seen");
                },
                cooldownKey: $"{record.Source}:{host}:{ecosystem}");
        }
    }
}
