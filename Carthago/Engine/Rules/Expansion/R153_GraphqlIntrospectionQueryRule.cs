// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R153_GraphqlIntrospectionQueryRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R153_GraphqlIntrospectionQueryRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R153",
            Name: "GraphQL Introspection Query",
            Category: "HttpApi",
            Description: "Detects explicit GraphQL introspection requests on cross-boundary HTTP flows instead of relying on loose GraphQL text alone.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R153.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R153",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The record must have HTTP context and target a GraphQL endpoint.",
                "The URI, header summary, or parser info must contain an explicit introspection token such as __schema or IntrospectionQuery.",
                "The flow must cross an internal/external boundary to suppress ordinary internal developer traffic."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic GraphQL requests with no introspection indicators.",
                "Do not alert from AnyText-only inputs with no HTTP path or boundary context."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "source+host+path",
            falsePositives: new[]
            {
                "Developer tooling and approved schema inspection on sanctioned external GraphQL services can look similar."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive cross-boundary graphql introspection sample",
                "negative ordinary graphql query sample"
            });

        public R153_GraphqlIntrospectionQueryRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch151155Evidence.HttpRequest(record)
                || !NetworkBatch151155Evidence.GraphqlPath(record)
                || !NetworkBatch151155Evidence.IntrospectionQuery(record)
                || !NetworkBatch126130Evidence.CrossBoundary(record, out var outboundToExternal, out var inboundFromExternal))
                return NoMatch();

            var conditions = new List<string> { "typed_http_request", "graphql_endpoint", "observed_introspection_query", "cross_boundary" };
            if (outboundToExternal) conditions.Add("outbound_to_external");
            if (inboundFromExternal) conditions.Add("inbound_from_external");
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", conditions), "rule"),
                new("http.path", "/graphql", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "An attributed cross-boundary GraphQL request contained an explicit introspection query parameter.",
                "Severity is Medium because introspection can assist API discovery, but is common in approved developer workflows.",
                "No typed HTTP body field exists in the current model; body-only introspection cannot be proven here.",
                "Check whether developer tooling and schema inspection are authorized.",
                "Review nearby GraphQL operations and authentication context."));
            return MatchHttpApi(context, SeverityLevel.Medium, "GraphQL introspection parameter observed",
                "GraphQLIntrospection", evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.28, "graphql-path");
                    confidence.AddEvidence(0.28, "introspection-indicator");
                    confidence.AddEvidence(0.18, "boundary-crossing");
                }, cooldownKey: NetworkBatch131135Evidence.Fingerprint(
                    $"{record.Source}:{record.Destination}:{record.DestinationPort}:graphql"));
        }
    }
}
