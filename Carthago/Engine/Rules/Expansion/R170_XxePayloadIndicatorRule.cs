// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R170_XxePayloadIndicatorRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R170_XxePayloadIndicatorRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R170",
            Name: "XXE Payload Indicator",
            Category: "HttpApi",
            Description: "Detects XML or SOAP requests with explicit XXE payload indicators instead of matching raw xxe text alone.",
            DefaultSeverity: SeverityLevel.High,
            ConfigKey: "Rules.R170.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R170",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Payload },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The request must be an XML or SOAP submission over HTTP.",
                "The URI, header summary, or parser info must contain explicit XXE constructs such as DOCTYPE, ENTITY, or file:// retrieval.",
                "AnyText-only xxe references without XML request context should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary XML or SOAP requests with no XXE constructs.",
                "Do not alert on free-form mentions of XXE without HTTP request context."
            },
            minimumConfidence: 80,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Security testing and intentionally malicious lab payloads can match. Validate whether the source is a sanctioned scanner."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive xml xxe payload sample",
                "negative ordinary xml sample"
            });

        public R170_XxePayloadIndicatorRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!HasHttpContext(record) || !HasMethod(record, "POST", "PUT", "PATCH"))
                return NoMatch();

            if (!(HasXmlContentType(record) || HasSoapContext(record)) || !HasXxeIndicator(record))
                return NoMatch();

            var path = HttpPath(record);
            var matchedConditions = new List<string> { "xml_or_soap_context", "xxe_indicator" };
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", string.Join(",", matchedConditions), "rule"),
                new("http.path", string.IsNullOrWhiteSpace(path) ? "/" : path, "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "An XML or SOAP HTTP request carried explicit XXE constructs such as DOCTYPE or ENTITY with local file retrieval semantics.",
                "Severity is High because XXE payloads can expose local files, cloud metadata, or backend network services.",
                "Security testing tools and lab replay traffic can intentionally submit XXE payloads.",
                "Confirm whether the target parser should ever receive arbitrary XML or SOAP content from this source.",
                "Review for adjacent SOAPAction abuse, metadata access, or open redirect activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.High,
                "XXE-style XML payload observed",
                "XxePayload",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.24, "xml-or-soap-context");
                    confidence.AddEvidence(0.30, "xxe-indicator");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{path}");
        }
    }
}
