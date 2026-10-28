// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R247_SshScpHighVolumeEgressRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R247_SshScpHighVolumeEgressRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R247", "SSH SCP High Volume Egress", "ExfiltrationAdvanced", "Detects high-volume SSH/SCP/SFTP egress from internal hosts to external targets with process or protocol evidence.", SeverityLevel.High, "Rules.R247.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R247", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Process }, new[] { "source", "external_destination", "ssh_scp_context", "bytes" }, new[] { "network.destinationPort", "flow.bytes", "process.name", "matched_conditions" }, new[] { "Traffic must be internal-to-external.", "SSH/SCP/SFTP context must be visible through port, protocol, service, process, or text evidence.", "Volume must exceed the high-egress threshold." }, new[] { "Do not alert on low-volume admin SSH.", "Do not alert on approved backup/replication identities." }, 82, 1, TimeSpan.FromMinutes(20), TimeSpan.FromMinutes(30), "source+destination+ssh", new[] { "Legitimate SFTP exports, offsite backup, and admin file transfer can match." }, new[] { "Mode", "HighVolumeBytes", "ApprovedSftpServers", "ApprovedAdminHosts" }, new[] { "positive high-volume scp sample", "negative low-volume ssh admin sample" });
        public R247_SshScpHighVolumeEgressRule() : base(Rule, Profile) { }
        private readonly NetworkBatch246250Evidence.ObservedByteWindow _bytes = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!NetworkBatch246250Evidence.SshClient(record)
                || IsLikelyApprovedSyncOrBackup(record)) return NoMatch();
            var observed = _bytes.Observe(record, context.TimestampUtc);
            if (observed < 150L * 1024 * 1024) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "scp_sftp_process,ssh_port,observed_packet_bytes", "rule"),
                new("flow.observedPacketBytes", observed.ToString(System.Globalization.CultureInfo.InvariantCulture), "flow"),
                new("flow.transfer_status", "packet_observations_only_unverified", "rule")
            };
            evidence.AddRange(AnalystContext("An attributed file-transfer client produced substantial SSH-port packet observations.",
                "Packet lengths are not TCP unique bytes or confirmed file-transfer volume.",
                "Authorized SFTP and backup activity may resemble this pattern.",
                "Corroborate with endpoint transfer logs and TCP sequence-aware flow totals."));
            return MatchExfiltration(context, SeverityLevel.High,
                "High observed SSH file-transfer client traffic", "SshScpHighVolumeEgress", evidence,
                c => { c.AddEvidence(0.26, "file-transfer-process"); c.AddEvidence(0.24, "observed-packet-volume"); c.AddEvidence(0.16, "external-ssh-destination"); },
                cooldownKey: record.Source + ":" + record.Destination + ":ssh-volume");

        }
    }
}
