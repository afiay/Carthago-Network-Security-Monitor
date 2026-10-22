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
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsLargeOutboundTransfer(record) || !LooksLikeArchiveTransfer(record) || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem>(TransferEvidence(record, "large_outbound_transfer,archive_indicator,unapproved_client"));
            evidence.AddRange(AnalystContext("A large archive-like object moved from an internal host to an external target.", "Severity is High because compressed archives are a common staging format for data theft.", "Approved backup/sync tools can match. Tune approved processes and destination roots explicitly.", "Validate the destination owner and business purpose.", "Inspect the archive name/path and source process.", "Check for prior staging, credential, or compression events on the source host."));
            return MatchExfiltration(context, SeverityLevel.High, "Large outbound archive transfer", "LargeArchiveEgress", evidence, c => { c.AddEvidence(0.28, "large-outbound-bytes"); c.AddEvidence(0.24, "archive-indicator"); c.AddEvidence(0.16, "unapproved-client"); }, cooldownKey: CooldownIdentity(record, "large-archive"));
        }
    }
}
