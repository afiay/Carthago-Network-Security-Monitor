// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R243_LargeOutboundArchiveTransferRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R243_LargeOutboundArchiveTransferRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R243", "Large Outbound Archive Transfer", "ExfiltrationAdvanced", "Detects large outbound archive transfers only when the transfer is external, archive-like, and not explained by approved sync or backup clients.", SeverityLevel.High, "Rules.R243.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R243", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Payload }, new[] { "source", "destination_or_host", "bytes", "archive_indicator" }, new[] { "flow.bytes", "file_or_path.indicator", "matched_conditions" }, new[] { "Internal source sends a large transfer to an external target.", "Filename, MIME, URI, or payload metadata indicates an archive.", "Approved sync or backup clients are suppressed." }, new[] { "Do not alert on ordinary browser downloads or approved backup/sync traffic.", "Do not alert on small archives without volume evidence." }, 82, 1, TimeSpan.FromMinutes(15), TimeSpan.FromMinutes(30), "source+destination+archive", new[] { "Approved backup jobs, software distribution, and sanctioned cloud sync can legitimately move large archives." }, new[] { "Mode", "LargeTransferBytes", "ApprovedSyncProcesses", "ApprovedDestinationRoots", "CooldownSeconds" }, new[] { "positive large outbound zip sample", "negative approved backup archive sample" });
        public R243_LargeOutboundArchiveTransferRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch241245Evidence.Archive(r) || !_replay.Observe(r, context.TimestampUtc))
                return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "external_http,archive_name,declared_large_body", "rule"),
                new("http.transfer_status", "request_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A cleartext HTTP upload request included a risk-relevant filename.",
                "Request metadata alone cannot prove payload transmission or successful exfiltration.",
                "Approved business exports and backup workflows can resemble this request.",
                "Review source, destination authorization and independent transfer evidence."));
            return MatchExfiltration(context, SeverityLevel.High, "Large archive upload request declared", "LargeArchiveEgress",
                evidence, c => { c.AddEvidence(0.28,"declared-large-body"); c.AddEvidence(0.24,"archive-filename"); c.AddEvidence(0.16,"upload-request"); },
                cooldownKey: r.Source + ":" + r.Destination + ":LargeArchiveEgress");
        }

    }
}
