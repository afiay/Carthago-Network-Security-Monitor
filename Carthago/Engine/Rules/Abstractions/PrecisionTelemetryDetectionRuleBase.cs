// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/PrecisionTelemetryDetectionRuleBase.cs
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public abstract class PrecisionTelemetryDetectionRuleBase : DetectionRuleBase
    {
        private readonly Lazy<RuleIntelligence> _intelligence;

        protected PrecisionTelemetryDetectionRuleBase(RuleDescriptor descriptor, RulePrecisionProfile precisionProfile)
        {
            Descriptor = descriptor ?? throw new ArgumentNullException(nameof(descriptor));
            PrecisionProfile = precisionProfile ?? throw new ArgumentNullException(nameof(precisionProfile));
            RulePrecisionCatalog.RegisterProfileOverride(PrecisionProfile);
            _intelligence = new Lazy<RuleIntelligence>(CreateIntelligence);
        }

        public sealed override RuleDescriptor Descriptor { get; }
        public RulePrecisionProfile PrecisionProfile { get; }
        public sealed override RuleIntelligence Intelligence => _intelligence.Value;

        protected virtual IReadOnlyList<RuleReference> AdditionalReferences => Array.Empty<RuleReference>();
        protected virtual IReadOnlyList<RuleTelemetryRequirement> AdditionalTelemetryRequirements => Array.Empty<RuleTelemetryRequirement>();
        protected virtual IReadOnlyList<RuleFalsePositiveNote> AdditionalKnownFalsePositives => Array.Empty<RuleFalsePositiveNote>();
        protected virtual IReadOnlyList<string> AdditionalTags => Array.Empty<string>();
        protected virtual string? InvestigationHintOverride => null;
        protected virtual string? TuningHintOverride => null;
        protected virtual int IntelligenceRevision => 2;

        public sealed override ValueTask<RuleEvaluationResult> EvaluateAsync(
            RuleEvaluationContext context,
            CancellationToken cancellationToken = default)
        {
            cancellationToken.ThrowIfCancellationRequested();
            return ValueTask.FromResult(EvaluatePrecision(context));
        }

        protected abstract RuleEvaluationResult EvaluatePrecision(RuleEvaluationContext context);

        protected virtual RuleIntelligence CreateIntelligence()
        {
            var baseline = RuleIntelligenceFactory.CreateDefault(Descriptor);
            return new RuleIntelligence
            {
                RuleId = Descriptor.RuleId,
                Maturity = baseline.Maturity,
                SignalKind = baseline.SignalKind,
                AttackTactics = baseline.AttackTactics,
                AttackTechniqueIds = baseline.AttackTechniqueIds,
                Tags = baseline.Tags.Concat(AdditionalTags).Distinct(StringComparer.OrdinalIgnoreCase).ToArray(),
                References = baseline.References.Concat(AdditionalReferences)
                    .GroupBy(static reference => reference.Url, StringComparer.OrdinalIgnoreCase)
                    .Select(static group => group.First())
                    .ToArray(),
                TelemetryRequirements = baseline.TelemetryRequirements.Concat(AdditionalTelemetryRequirements)
                    .GroupBy(static requirement => requirement.Name, StringComparer.OrdinalIgnoreCase)
                    .Select(static group => group.First())
                    .ToArray(),
                KnownFalsePositives = baseline.KnownFalsePositives.Concat(AdditionalKnownFalsePositives)
                    .GroupBy(static note => note.Scenario, StringComparer.OrdinalIgnoreCase)
                    .Select(static group => group.First())
                    .ToArray(),
                PrecisionProfile = PrecisionProfile,
                InvestigationHint = string.IsNullOrWhiteSpace(InvestigationHintOverride) ? baseline.InvestigationHint : InvestigationHintOverride!,
                TuningHint = string.IsNullOrWhiteSpace(TuningHintOverride) ? baseline.TuningHint : TuningHintOverride!,
                Revision = Math.Max(1, IntelligenceRevision)
            };
        }

        protected DetectionEvent CreateDetectionEvent(
            RuleEvaluationContext context,
            SeverityLevel severity,
            string summary,
            IEnumerable<DetectionEvidenceItem> evidenceItems,
            Action<ConfidenceBuilder>? configureConfidence = null,
            int count = 1,
            int windowSeconds = 0,
            DetectionSuppressionStatus suppressionStatus = DetectionSuppressionStatus.None)
        {
            if (context == null) throw new ArgumentNullException(nameof(context));

            var record = context.Record;
            // These rules can identify private DNS labels, token-bearing service
            // authorities, or sensitive file-transfer destinations. Redact only
            // event presentation: keep the original record for rule evaluation,
            // flow correlation and analyst investigation in its own access scope.
            var redactHost = RedactRuleHost(Descriptor.RuleId);
            var redactDestination = RedactRuleDestination(Descriptor.RuleId);
            var items = new List<DetectionEvidenceItem>
            {
                new("source", record.Source ?? "unknown", "traffic-record"),
                new("destination", redactDestination ? "[REDACTED]" : record.Destination ?? "unknown", "traffic-record"),
                new("destinationHost", redactHost ? "[REDACTED]" : FirstNonEmpty(record.DnsQname, record.HttpHost, record.Sni, record.Destination) ?? "unknown", "traffic-record"),
                new("protocol", FirstNonEmpty(record.ApplicationProtocol, record.ApplicationService, record.Protocol) ?? "unknown", "traffic-record")
            };

            if (evidenceItems != null)
            {
                foreach (var item in evidenceItems.Where(static item =>
                    !string.IsNullOrWhiteSpace(item.Key) && !string.IsNullOrWhiteSpace(item.Value)))
                {
                    // Subclasses may already redact their own fields. Do not
                    // permit another raw host or destination key to bypass the
                    // shared event boundary.
                    if ((redactHost && IsHostEvidenceKey(item.Key))
                        || (redactDestination && IsDestinationEvidenceKey(item.Key)))
                        items.Add(new DetectionEvidenceItem(item.Key, "[REDACTED]", item.Source));
                    else
                        items.Add(item);
                }
            }

            var summaryText = string.IsNullOrWhiteSpace(summary) ? Descriptor.Name : summary.Trim();
            var evt = new DetectionEvent
            {
                RuleId = Descriptor.RuleId,
                RuleName = Descriptor.Name,
                TimestampUtc = context.TimestampUtc,
                Severity = severity,
                SourceIp = record.Source,
                SourcePort = record.SourcePort,
                DestinationIp = record.Destination,
                DestinationHost = redactHost ? "[REDACTED]" : FirstNonEmpty(record.DnsQname, record.HttpHost, record.Sni, record.Destination),
                DestinationPort = record.DestinationPort,
                Protocol = FirstNonEmpty(record.ApplicationProtocol, record.ApplicationService, record.Protocol),
                ProcessName = record.ProcessName,
                Country = FirstNonEmpty(record.DstCountryIso2, record.DstCountry, record.WhoisCountry),
                Asn = record.WhoisASN,
                Ja4 = record.Ja4,
                Hassh = record.Hassh,
                QuicAlpn = record.QuicAlpn,
                QuicConnectionIdHash = record.QuicConnectionIdHash,
                PacketId = record.Id.ToString("N"),
                Summary = summaryText,
                Description = summaryText,
                Evidence = BuildLegacyEvidence(items),
                StructuredEvidence = new DetectionEvidenceSet(items, summaryText),
                Count = Math.Max(1, count),
                WindowSeconds = Math.Max(0, windowSeconds),
                DeliveryStatus = DetectionDeliveryStatus.Pending,
                SuppressionStatus = suppressionStatus
            };

            var intelligence = Intelligence;
            evt.RuleMaturityAtDetection = intelligence.Maturity.ToString();
            evt.RuleRevisionAtDetection = intelligence.Revision;

            AppendPrecisionProfileEvidence(evt);

            if (configureConfidence == null)
            {
                ConfidenceBuilder.ApplyDefault(evt, Descriptor, intelligence);
            }
            else
            {
                var builder = new ConfidenceBuilder();
                configureConfidence(builder);
                builder.ApplyTo(evt);
                if (evt.ConfidenceScore <= 0.0)
                    ConfidenceBuilder.ApplyDefault(evt, Descriptor, intelligence);
            }

            return evt;
        }

        protected void ShadowForWeakEvidence(DetectionEvent evt, string reason)
        {
            if (evt == null || string.IsNullOrWhiteSpace(reason))
                return;

            evt.SuppressionStatus = DetectionSuppressionStatus.Shadowed;
            EvidenceBuilder.AppendEvidence(evt, "suppression.reason", reason.Trim(), "precision-runtime");
        }

        protected void SuppressForCooldown(DetectionEvent evt, string reason)
        {
            if (evt == null || string.IsNullOrWhiteSpace(reason))
                return;

            evt.SuppressionStatus = DetectionSuppressionStatus.Suppressed;
            EvidenceBuilder.AppendEvidence(evt, "suppression.reason", reason.Trim(), "precision-runtime");
        }

        private void AppendPrecisionProfileEvidence(DetectionEvent evt)
        {
            EvidenceBuilder.AppendEvidence(evt, "precision.maturity", PrecisionProfile.Maturity.ToString(), "rule-precision-profile");
            EvidenceBuilder.AppendEvidence(evt, "precision.defaultMode", PrecisionProfile.DefaultMode.ToString(), "rule-precision-profile");
            EvidenceBuilder.AppendEvidence(evt, "precision.minimumConfidence", PrecisionProfile.MinimumConfidence.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (PrecisionProfile.Threshold.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "precision.threshold", PrecisionProfile.Threshold.Value.ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (PrecisionProfile.Window.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "precision.windowSeconds", ((int)PrecisionProfile.Window.Value.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (PrecisionProfile.Cooldown.HasValue)
                EvidenceBuilder.AppendEvidence(evt, "precision.cooldownSeconds", ((int)PrecisionProfile.Cooldown.Value.TotalSeconds).ToString(System.Globalization.CultureInfo.InvariantCulture), "rule-precision-profile");
            if (!string.IsNullOrWhiteSpace(PrecisionProfile.DistinctBy))
                EvidenceBuilder.AppendEvidence(evt, "precision.distinctBy", PrecisionProfile.DistinctBy!, "rule-precision-profile");
        }

        private static bool RedactRuleHost(string ruleId)
        {
            if (!ruleId.StartsWith("R", StringComparison.Ordinal)
                || !int.TryParse(ruleId.AsSpan(1), out var number))
                return false;
            return number is >= 178 and <= 197
                or >= 201 and <= 222
                or >= 243 and <= 257
                or 353 or 354;
        }

        private static bool RedactRuleDestination(string ruleId)
            => ruleId is "R248" or "R249" or "R250";

        private static bool IsHostEvidenceKey(string key)
            => key.Equals("destinationHost", StringComparison.OrdinalIgnoreCase)
                || key.Equals("network.bestHost", StringComparison.OrdinalIgnoreCase)
                || key.Equals("clouddev.host", StringComparison.OrdinalIgnoreCase)
                || key.Equals("httpapi.host", StringComparison.OrdinalIgnoreCase)
                || key.Equals("http.host", StringComparison.OrdinalIgnoreCase)
                || key.Equals("tls.host", StringComparison.OrdinalIgnoreCase)
                || key.Equals("tls.sni", StringComparison.OrdinalIgnoreCase)
                || key.Equals("dns.qname", StringComparison.OrdinalIgnoreCase)
                || key.Equals("dns.rootDomain", StringComparison.OrdinalIgnoreCase)
                || key.Equals("dns.answers", StringComparison.OrdinalIgnoreCase);

        private static bool IsDestinationEvidenceKey(string key)
            => key.Equals("destination", StringComparison.OrdinalIgnoreCase)
                || key.Equals("network.destination", StringComparison.OrdinalIgnoreCase);

        private static string BuildLegacyEvidence(IEnumerable<DetectionEvidenceItem> items)
            => string.Join("; ", items
                .Where(static item => !item.IsSensitive)
                .Select(static item => $"{item.Key}={item.Value}")
                .Take(24));

        protected static string? FirstNonEmpty(params string?[] values)
            => values.FirstOrDefault(static value => !string.IsNullOrWhiteSpace(value));
    }
}
