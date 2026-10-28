// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R257_ExfiltrationAfterCredentialAlertChainRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R257_ExfiltrationAfterCredentialAlertChainRule : ExfiltrationAdvancedPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new("R257", "Exfiltration After Credential Alert Chain", "ExfiltrationAdvanced", "Detects exfiltration-like egress when the same record/source carries credential-compromise context or recent credential-alert indicators.", SeverityLevel.Critical, "Rules.R257.Enabled", true);
        private static readonly RulePrecisionProfile Profile = CreateExfiltrationProfile("R257", RulePrecisionMaturity.Validated, RuleRuntimeMode.Alert, new[] { RuleTelemetryKind.Flow, RuleTelemetryKind.Http, RuleTelemetryKind.Identity, RuleTelemetryKind.Payload }, new[] { "source", "credential_alert_indicator", "external_egress", "exfil_indicator" }, new[] { "matched_conditions", "flow.bytes", "file_or_path.indicator" }, new[] { "Credential-compromise context must be present in observable telemetry or upstream alert text.", "External egress must be upload-like, bulk, archive-like, sensitive-file-like, or encoded.", "Rule should not infer a chain from source identity alone." }, new[] { "Do not alert on credential alerts without egress.", "Do not alert on egress without credential-compromise context." }, 88, 1, TimeSpan.FromHours(2), TimeSpan.FromHours(1), "source+credential_chain+destination", new[] { "Incident notes or test data containing credential keywords can match if fed into traffic info fields." }, new[] { "Mode", "ChainWindow", "MinimumBytes", "CredentialRuleIds", "CooldownSeconds" }, new[] { "positive credential alert followed by archive upload sample", "negative credential alert without egress sample" });
        public R257_ExfiltrationAfterCredentialAlertChainRule() : base(Rule, Profile) { }
        private readonly NetworkBatch156165ReplayGuard _replay = new();
        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var r = context.Record;
            if (!NetworkBatch256260Evidence.CredentialProcessAndUploadRequest(r)
                || !_replay.Observe(r, context.TimestampUtc)) return NoMatch();
            var evidence = new List<DetectionEvidenceItem> {
                new("matched_conditions", "credential_tool_process,parsed_external_http_upload_request", "rule"),
                new("credential.alertCorrelation", "not_observed", "rule"),
                new("http.bodyStatus", "declared_not_transferred", "http")
            };
            evidence.AddRange(AnalystContext("A credential-associated process name and an external cleartext HTTP upload request were co-observed.",
                "No trusted upstream credential alert or successful exfiltration is established by this record.",
                "Process enrichment is not independently verified; legitimate security tests may match.",
                "Verify process provenance and correlate against approved timestamped credential alerts."));
            return MatchExfiltration(context, SeverityLevel.Critical,
                "Credential-tool process with external HTTP upload request (alert chain unverified)",
                "CredentialToExfilChain", evidence,
                c => { c.AddEvidence(0.30, "exact-process-name"); c.AddEvidence(0.26, "parsed-upload-request"); c.AddEvidence(0.18, "external-destination"); },
                cooldownKey: CooldownIdentity(r, "credential-upload-coobservation"));
        }
    }
}
