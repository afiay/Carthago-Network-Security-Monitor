// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R168_BackupArchiveDownloadProbeRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R168_BackupArchiveDownloadProbeRule : HttpApiPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R168",
            Name: "Backup Archive Download Probe",
            Category: "HttpApi",
            Description: "Detects cross-boundary requests for filenames that strongly resemble database or site backups instead of every archive download.",
            DefaultSeverity: SeverityLevel.Medium,
            ConfigKey: "Rules.R168.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateHttpApiProfile(
            ruleId: "R168",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Shadow,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow },
            requiredFields: new[] { "source", "destination_or_host", "http_any" },
            evidenceFields: new[] { "matched_conditions", "http.path" },
            positiveConditions: new[]
            {
                "The flow must cross an internal/external boundary.",
                "The requested filename must strongly resemble a backup, dump, or database archive rather than an ordinary user download.",
                "Generic zip or tar downloads should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on ordinary download/report archives.",
                "Do not alert when the filename lacks backup, dump, or database semantics."
            },
            minimumConfidence: 72,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(10),
            distinctBy: "host+path",
            falsePositives: new[]
            {
                "Approved backup portals and internal recovery workflows may legitimately fetch backup archives."
            },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[]
            {
                "positive backup archive filename sample",
                "negative ordinary report archive sample"
            });

        private readonly NetworkBatch156165ReplayGuard _replay = new();

        public R168_BackupArchiveDownloadProbeRule()
            : base(Rule, Profile)
        {
        }

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch166170Evidence.Http(record) || !HasMethod(record, "GET", "HEAD") || !NetworkBatch166170Evidence.Backup(record))
                return NoMatch();

            if (!NetworkBatch166170Evidence.Inbound(record))
                return NoMatch();

            if (!_replay.Observe(record, context.TimestampUtc)) return NoMatch();
            var path = HttpPath(record);
            var evidenceItems = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", "backup_archive_filename,boundary_crossing", "rule"),
                new("http.path", "[REDACTED]", "http")
            };
            evidenceItems.AddRange(AnalystContext(
                "A cross-boundary request targeted a filename that strongly resembles a database or site backup archive.",
                "Severity is Medium because exposed backups often contain complete application data, credentials, and configuration state.",
                "Approved recovery portals can distribute backup files legitimately. Validate whether the target host is a sanctioned backup surface.",
                "Confirm whether the requested archive is expected to be reachable from the requesting source.",
                "Review for adjacent .git, .env, phpinfo, or admin login probes from the same source."));

            return MatchHttpApi(
                context,
                SeverityLevel.Medium,
                "Backup-style archive path requested",
                "BackupArchiveProbe",
                evidenceItems,
                confidence =>
                {
                    confidence.AddEvidence(0.26, "backup-archive-filename");
                    confidence.AddEvidence(0.16, "boundary-crossing");
                },
                cooldownKey: $"{record.Source}:{BestHost(record)}:{NetworkBatch166170Evidence.Key(path)}");
        }
    }
}
