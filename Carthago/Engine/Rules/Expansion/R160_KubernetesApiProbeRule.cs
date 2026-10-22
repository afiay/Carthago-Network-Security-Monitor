// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R160_KubernetesApiProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R160_KubernetesApiProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R160",
            Name: "Kubernetes API Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary requests to concrete Kubernetes API paths instead of generic /api traffic.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R160.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R160",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The request must target a known Kubernetes API path and a Kubernetes-like host or port.",
                "Generic REST application paths should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary /api application traffic that is unrelated to Kubernetes.",
                "Do not alert when there is no Kubernetes path and environment context."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Cluster admins and approved automation may legitimately query Kubernetes APIs. Validate the source identity or process."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive kubernetes api path sample",
                "negative generic application api sample"
            });

        public R160_KubernetesApiProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !IsKubernetesApiProbe(record))
                return NoMatch();

            if (!IsCrossBoundary(record, out _, out _))
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "kubernetes_api_path,boundary_crossing", "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "network")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary HTTP request targeted a concrete Kubernetes API path.",
                "Severity is High because Kubernetes API discovery often precedes secrets access, workload manipulation, or token abuse.",
                "Approved cluster automation, CI/CD agents, and operators can legitimately access these endpoints.",
                "Confirm whether the source host or process is an approved cluster administration path.",
                "Review for adjacent service account, secret, or pod-management requests."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Kubernetes API probe observed",
                "KubernetesApiProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "kubernetes-api-path");
                    confidence.AddEvidence(0.20, "kubernetes-port-or-host");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
