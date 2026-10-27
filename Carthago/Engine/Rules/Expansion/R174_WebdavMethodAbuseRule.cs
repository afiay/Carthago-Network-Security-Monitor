// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R174_WebdavMethodAbuseRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R174_WebdavMethodAbuseRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R174",
            Name: "WebDAV Method Abuse",
            Category: "HttpApi",
            Description: "Detects suspicious WebDAV verbs and Depth: infinity style probes instead of every WebDAV-related request.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R174.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R174",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.method", "http.path" },
            positiveConditions: new[]
            {
                "The request must use a concrete WebDAV verb or PROPFIND with strong abusive context.",
                "The flow must cross an internal/external boundary.",
                "Benign CalDAV and CardDAV discovery paths should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on benign well-known DAV discovery.",
                "Do not alert on plain GET or POST requests with no WebDAV semantics."
            },
            minimumConfidence: 74,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path+method",
            falsePositives: new[]
            {
                "Approved file sync, SharePoint-like, or DAV clients can legitimately use WebDAV verbs."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive suspicious webdav method sample",
                "negative benign caldav discovery sample"
            });

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        public R174_WebdavMethodAbuseRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch171175Evidence.DavHttp(record) || !NetworkBatch171175Evidence.DavAbuse(record))
                return NoMatch();

            if (!NetworkBatch171175Evidence.Inbound(record))
                return NoMatch();

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "suspicious_webdav_method,boundary_crossing", "rule"),
                new("http.path", "[REDACTED]", "http"),
                new("http.method", record.HttpMethod ?? "unknown", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary HTTP request used suspicious WebDAV verb semantics or deep PROPFIND behavior.",
                "Severity is Medium because abusive WebDAV verbs are commonly used for discovery, unauthorized file writes, or lateral staging.",
                "Legitimate DAV sync clients can use these verbs. Validate the source process, user agent, and destination before escalating.",
                "Confirm whether the destination should accept WebDAV traffic from the source.",
                "Review adjacent file upload, admin login, and request smuggling activity from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Suspicious WebDAV method observed",
                "WebDavAbuse",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.20, "suspicious-webdav-method");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{record.HttpMethod}:{NetworkBatch166170Evidence.Key(path)}");
        }
    }
}
