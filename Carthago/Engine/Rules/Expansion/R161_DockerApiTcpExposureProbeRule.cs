// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R161_DockerApiTcpExposureProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R161_DockerApiTcpExposureProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R161",
            Name: "Docker API TCP Exposure Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary requests to Docker daemon API paths on Docker-like hosts or ports instead of loose /version matching.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R161.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R161",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path", "network.destinationPort" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The request must target a Docker daemon API path and a Docker-related host or port.",
                "Generic /version paths on ordinary web applications should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary application version endpoints.",
                "Do not alert when there is no Docker API path or Docker daemon port context."
            },
            minimumConfidence: 78,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved container orchestration or support tooling may query Docker daemon APIs."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive docker api path sample",
                "negative ordinary version endpoint sample"
            });

        public R161_DockerApiTcpExposureProbeRule()
            : base(Rule, Profile)
        {
        }

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch156165Evidence.Http(record) || !NetworkBatch156165Evidence.Docker(record))
                return NoMatch();

            if (!NetworkBatch126130Evidence.CrossBoundary(record, out _, out var inbound) || !inbound)
                return NoMatch();

            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "docker_api_path,boundary_crossing", "rule"),
                new("http.routeCategory", "docker_daemon", "http"),
                new("network.destinationPort", (record.DestinationPort ?? 0).ToString(System.Globalization.CultureInfo.InvariantCulture), "network")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted a Docker daemon API path.",
                "Severity is High because exposed Docker APIs can allow container enumeration, image pulls, and direct workload execution.",
                "Approved automation or container management tooling may legitimately access Docker APIs.",
                "Confirm whether the source belongs to a sanctioned container administration workflow.",
                "Review for follow-on container create, exec, or image pull calls from the same source."));

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "Docker daemon API probe observed",
                "DockerApiProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "docker-api-path");
                    confidence.AddEvidence(0.20, "docker-port-or-host");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
