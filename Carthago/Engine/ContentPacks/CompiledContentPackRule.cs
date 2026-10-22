// SPDX-License-Identifier: MIT
// File: Engine/ContentPacks/CompiledContentPackRule.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Engine.ContentPacks
{
    public sealed class CompiledContentPackRule : DetectionRuleBase, IContentPackRule
    {
        private readonly ContentPackRule _definition;
        private readonly IDetectionRule _sourceRule;
        private readonly RuleIntelligence _intelligence;
        private readonly RuleDescriptor _descriptor;

        public CompiledContentPackRule(string packId, ContentPackRule definition, IDetectionRule sourceRule)
        {
            PackId = packId ?? throw new ArgumentNullException(nameof(packId));
            _definition = definition ?? throw new ArgumentNullException(nameof(definition));
            _sourceRule = sourceRule ?? throw new ArgumentNullException(nameof(sourceRule));
            SourceRuleId = sourceRule.Descriptor.RuleId;
            Deprecated = definition.Deprecated;
            _descriptor = new RuleDescriptor(
                RuleId: definition.RuleId,
                Name: string.IsNullOrWhiteSpace(definition.Name) ? sourceRule.Descriptor.Name : definition.Name,
                Category: string.IsNullOrWhiteSpace(definition.Category) ? sourceRule.Descriptor.Category : definition.Category,
                Description: string.IsNullOrWhiteSpace(definition.Description) ? sourceRule.Descriptor.Description : definition.Description,
                DefaultSeverity: definition.DefaultSeverity,
                ConfigKey: $"ContentPacks.{PackId}.Rules.{definition.RuleId}.Enabled",
                EnabledByDefault: false);
            _intelligence = CreateIntelligence();
        }

        public override RuleDescriptor Descriptor => _descriptor;
        public override RuleIntelligence Intelligence => _intelligence;
        public string PackId { get; }
        public string SourceRuleId { get; }
        public bool Deprecated { get; }

        public override async ValueTask<RuleEvaluationResult> EvaluateAsync(RuleEvaluationContext context, CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            var result = await _sourceRule.EvaluateAsync(context, cancellationToken).ConfigureAwait(false);
            if (!result.Matched || result.Events.Count == 0)
            {
                return result.Failed
                    ? RuleEvaluationResult.FailedRule(_descriptor.RuleId, result.FailureMessage ?? "Source rule evaluation failed.")
                    : result.Skipped
                        ? RuleEvaluationResult.SkippedDisabled(_descriptor.RuleId)
                        : RuleEvaluationResult.NoMatch(_descriptor.RuleId);
            }

            var translated = result.Events.Select(CloneEvent).ToArray();
            return RuleEvaluationResult.Match(_descriptor.RuleId, translated);
        }

        private RuleIntelligence CreateIntelligence()
        {
            var source = _sourceRule.Intelligence;
            var telemetry = _definition.TelemetryRequirements.Count > 0
                ? _definition.TelemetryRequirements
                : source.TelemetryRequirements;
            var references = source.References
                .Concat(_definition.References)
                .GroupBy(static item => item.Url, StringComparer.OrdinalIgnoreCase)
                .Select(static group => group.First())
                .ToArray();
            var fps = source.KnownFalsePositives
                .Concat(_definition.KnownFalsePositives)
                .GroupBy(static item => item.Scenario, StringComparer.OrdinalIgnoreCase)
                .Select(static group => group.First())
                .ToArray();

            return source with
            {
                RuleId = _descriptor.RuleId,
                Maturity = Deprecated ? RuleMaturity.Deprecated : source.Maturity,
                Tags = source.Tags.Concat(new[] { $"content-pack:{PackId}", $"content-pack-rule:{_descriptor.RuleId}" }).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                References = references,
                TelemetryRequirements = telemetry.ToArray(),
                KnownFalsePositives = fps,
                InvestigationHint = $"{source.InvestigationHint} Pack context: {PackId}. Source rule: {SourceRuleId}.",
                TuningHint = $"{source.TuningHint} Pack defaults come from {PackId} profile guidance.",
                Revision = Math.Max(1, source.Revision)
            };
        }

        private DetectionEvent CloneEvent(DetectionEvent source)
        {
            var evidenceItems = source.StructuredEvidence?.Items?.ToList() ?? new List<DetectionEvidenceItem>();
            evidenceItems.Add(new DetectionEvidenceItem("content_pack_id", PackId, "content-pack"));
            evidenceItems.Add(new DetectionEvidenceItem("content_pack_source_rule_id", SourceRuleId, "content-pack"));

            return new DetectionEvent
            {
                EventId = Guid.NewGuid().ToString("N"),
                TimestampUtc = source.TimestampUtc,
                RuleId = _descriptor.RuleId,
                RuleName = _descriptor.Name,
                Summary = source.Summary,
                Description = source.Description,
                SourceIp = source.SourceIp,
                SourcePort = source.SourcePort,
                DestinationIp = source.DestinationIp,
                DestinationHost = source.DestinationHost,
                DestinationPort = source.DestinationPort,
                Protocol = source.Protocol,
                ProcessName = source.ProcessName,
                Country = source.Country,
                Asn = source.Asn,
                Ja4 = source.Ja4,
                Hassh = source.Hassh,
                QuicAlpn = source.QuicAlpn,
                QuicConnectionIdHash = source.QuicConnectionIdHash,
                PacketId = source.PacketId,
                FlowId = source.FlowId,
                CorrelationId = source.CorrelationId,
                Evidence = source.Evidence,
                StructuredEvidence = new DetectionEvidenceSet(evidenceItems, source.StructuredEvidence?.Summary ?? source.Summary),
                ConfidenceScore = source.ConfidenceScore,
                ConfidenceLabel = source.ConfidenceLabel,
                EvidenceScore = source.EvidenceScore,
                BaselineScore = source.BaselineScore,
                ThreatIntelScore = source.ThreatIntelScore,
                CorrelationScore = source.CorrelationScore,
                RuleMaturityAtDetection = Intelligence.Maturity.ToString(),
                RuleRevisionAtDetection = Intelligence.Revision,
                JournalPath = source.JournalPath,
                PersistedAtUtc = source.PersistedAtUtc,
                PersistenceError = source.PersistenceError,
                DeliveryStatus = source.DeliveryStatus,
                SuppressionStatus = source.SuppressionStatus,
                ExternalDeliveryStatus = source.ExternalDeliveryStatus,
                LastSinkName = source.LastSinkName,
                LastSinkError = source.LastSinkError,
                LastSinkAttemptUtc = source.LastSinkAttemptUtc,
                SinkSuccessCount = source.SinkSuccessCount,
                SinkFailureCount = source.SinkFailureCount,
                SensorId = source.SensorId,
                SiteId = source.SiteId,
                TenantId = source.TenantId,
                CaptureInterface = source.CaptureInterface,
                SensorVersion = source.SensorVersion,
                SensorClockSkewMs = source.SensorClockSkewMs,
                IngestionTimestampUtc = source.IngestionTimestampUtc,
                Severity = source.Severity,
                Count = source.Count,
                WindowSeconds = source.WindowSeconds,
                SensitivityAtTrigger = source.SensitivityAtTrigger
            };
        }
    }
}
