// SPDX-License-Identifier: MIT
// File: Services/Environment/DetectionEvidenceEnricher.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Health;
using Carthago.Models;

namespace Carthago.Services.EnvironmentTuning
{
    public static class DetectionEvidenceEnricher
    {
        public static void ApplyEnvironmentAndTelemetryEvidence(
            DetectionEvent? evt,
            RuleDescriptor descriptor,
            TrafficRecord? record,
            EnvironmentAssessment? assessment = null,
            RuleTelemetryCoverageImpact? coverage = null)
        {
            if (evt == null || record == null)
                return;

            EvidenceBuilder.EnsureStructuredEvidence(evt);
            var items = evt.StructuredEvidence?.Items?.ToList() ?? new List<DetectionEvidenceItem>();

            assessment ??= EnvironmentAssessmentService.Current.Assess(record);
            items.AddRange(assessment.EvidenceItems);

            var observedKinds = Enum.GetValues(typeof(RuleTelemetryKind))
                .Cast<RuleTelemetryKind>()
                .Where(kind => RulePrecisionCatalog.HasTelemetryKind(kind, record))
                .Select(static kind => kind.ToString())
                .ToArray();

            if (observedKinds.Length > 0)
                items.Add(new DetectionEvidenceItem("telemetry.observed", string.Join(",", observedKinds), "telemetry"));

            coverage ??= BuildCoverage(descriptor, record);
            items.Add(new DetectionEvidenceItem("telemetry.coverage_state", coverage.State.ToString(), "telemetry"));
            items.Add(new DetectionEvidenceItem("telemetry.coverage_ratio", coverage.CoverageRatio.ToString("0.00"), "telemetry"));
            if (coverage.MissingRequiredTelemetry.Count > 0)
                items.Add(new DetectionEvidenceItem("telemetry.missing_required", string.Join(",", coverage.MissingRequiredTelemetry), "telemetry"));

            evt.StructuredEvidence = new DetectionEvidenceSet(Deduplicate(items), evt.StructuredEvidence?.Summary ?? evt.Summary ?? evt.Evidence ?? string.Empty);

            if (assessment.RiskModifiers.Count > 0)
                AppendLegacyEvidence(evt, "environment.modifiers", string.Join(",", assessment.RiskModifiers));
            if (coverage.MissingRequiredTelemetry.Count > 0)
                AppendLegacyEvidence(evt, "telemetry.missing_required", string.Join(",", coverage.MissingRequiredTelemetry));
        }

        private static RuleTelemetryCoverageImpact BuildCoverage(RuleDescriptor descriptor, TrafficRecord record)
        {
            var profile = RulePrecisionCatalog.GetProfile(descriptor);
            var required = profile.RequiredTelemetry.OrderBy(static kind => kind.ToString(), StringComparer.OrdinalIgnoreCase).ToArray();
            var observed = required.Where(kind => RulePrecisionCatalog.HasTelemetryKind(kind, record)).ToArray();
            var missing = required.Except(observed).ToArray();
            var missingFields = profile.RequiredFields.Where(field => !RulePrecisionCatalog.HasField(field, record)).ToArray();
            var state = required.Length == 0
                ? RuleTelemetryCoverageState.Full
                : observed.Length == 0
                    ? RuleTelemetryCoverageState.Unsupported
                    : observed.Length == required.Length && missingFields.Length == 0
                        ? RuleTelemetryCoverageState.Full
                        : RuleTelemetryCoverageState.Partial;

            return new RuleTelemetryCoverageImpact(descriptor.RuleId, state, required, observed, missing, missingFields, DateTime.UtcNow);
        }

        private static IReadOnlyList<DetectionEvidenceItem> Deduplicate(IEnumerable<DetectionEvidenceItem> items)
        {
            return items
                .Where(static item => !string.IsNullOrWhiteSpace(item.Key) && !string.IsNullOrWhiteSpace(item.Value))
                .GroupBy(static item => item.Key + "\u001f" + item.Value + "\u001f" + item.Source, StringComparer.OrdinalIgnoreCase)
                .Select(static group => group.First())
                .Take(128)
                .ToArray();
        }

        private static void AppendLegacyEvidence(DetectionEvent evt, string key, string value)
        {
            var pair = key + "=" + value;
            if (string.IsNullOrWhiteSpace(evt.Evidence))
                evt.Evidence = pair;
            else if (evt.Evidence.IndexOf(pair, StringComparison.OrdinalIgnoreCase) < 0)
                evt.Evidence += "; " + pair;
        }
    }
}
