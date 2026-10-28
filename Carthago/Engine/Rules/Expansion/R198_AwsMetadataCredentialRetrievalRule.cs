// SPDX-License-Identifier: MIT
// File: Engine/Rules/Expansion/R198_AwsMetadataCredentialRetrievalRule.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Engine.Rules.Expansion
{
    public sealed class R198_AwsMetadataCredentialRetrievalRule : CloudDevPrecisionDetectionRuleBase
    {
        private static readonly RuleDescriptor Rule = new(
            RuleId: "R198",
            Name: "AWS Metadata Credential Retrieval",
            Category: "CloudDev",
            Description: "Detects direct IMDS credential-path access on AWS metadata targets, while suppressing expected cloud agent activity.",
            DefaultSeverity: SeverityLevel.Critical,
            ConfigKey: "Rules.R198.Enabled",
            EnabledByDefault: true);

        private static readonly RulePrecisionProfile Profile = CreateCloudDevProfile(
            ruleId: "R198",
            maturity: RulePrecisionMaturity.Validated,
            defaultMode: RuleRuntimeMode.Alert,
            requiredTelemetry: new[] { RuleTelemetryKind.Http, RuleTelemetryKind.Flow, RuleTelemetryKind.Payload, RuleTelemetryKind.CloudAudit },
            requiredFields: new[] { "source", "destination_or_host", "http_any", "payload_or_uri" },
            evidenceFields: new[] { "http.path", "matched_conditions" },
            positiveConditions: new[]
            {
                "The record must target the AWS metadata endpoint or equivalent EC2 metadata host.",
                "The HTTP path must reach IMDS credential or instance-identity material.",
                "Known cloud-management agents should remain suppressed."
            },
            negativeConditions: new[]
            {
                "Do not alert on generic HTTP traffic to link-local addresses without the credential path.",
                "Do not alert on expected cloud-init or SSM metadata access."
            },
            minimumConfidence: 88,
            threshold: 1,
            window: TimeSpan.FromMinutes(15),
            cooldown: TimeSpan.FromMinutes(20),
            distinctBy: "source+host",
            falsePositives: new[] { "Expected EC2 guest agents and approved bootstrap workflows can access IMDS legitimately." },
            tuningKnobs: new[] { "Mode", "CooldownSeconds" },
            requiredTests: new[] { "positive aws imds credential request sample", "negative approved metadata agent sample" });

        public R198_AwsMetadataCredentialRetrievalRule() : base(Rule, Profile) { }

        private readonly NetworkBatch181185Window _window = new();

        protected override RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context)
        {
            var record = context.Record;
            if (!IsAwsMetadataCredentialRequest(record)
                || !NetworkBatch196200Evidence.MetadataRequest(record, "aws")
                || _window.Observe(record, $"{Descriptor.RuleId}:{record.Source}:{record.Destination}",
                    record.HttpUri ?? "", context.TimestampUtc, TimeSpan.FromMinutes(15), distinct: false) == 0)
                return NoMatch();

            var hasImdsv2Token = NetworkBatch166170Evidence.Header(record, "X-aws-ec2-metadata-token", out var token)
                && !string.IsNullOrWhiteSpace(token);

            var evidence = new List<DetectionEvidenceItem>
            {
                new("matched_conditions", hasImdsv2Token ? "aws_imds_target,credential_path,imdsv2_token" : "aws_imds_target,credential_path", "rule")
            };
            evidence.AddRange(AnalystContext(
                "A typed HTTP request targeted an AWS IMDS role-credential endpoint; response content and credential issuance were not observed.",
                "Severity is Critical because IMDS credential retrieval can expose temporary IAM credentials for privilege escalation or cloud exfiltration.",
                "Expected cloud bootstrap or management agents can touch IMDS. Validate the calling process and instance role before escalating.",
                "Review the calling process and subsequent AWS API usage from the same host.",
                "Confirm whether the instance role credentials were subsequently used externally."));

            return MatchHttpApi(
                context,
                SeverityLevel.Critical,
                "AWS metadata credential retrieval observed",
                "AwsMetadataCredentials",
                evidence,
                confidence =>
                {
                    confidence.AddEvidence(0.30, "aws-imds-target");
                    confidence.AddEvidence(0.28, "credential-path");
                    if (hasImdsv2Token) confidence.AddEvidence(0.10, "imdsv2-token");
                },
                cooldownKey: $"{record.Source}:{record.Destination}");
        }
    }
}
