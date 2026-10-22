// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/ConfidenceBuilder.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public sealed class ConfidenceBuilder
    {
        private readonly List<string> _reasons = new();
        private double _evidenceScore;
        private double _baselineScore;
        private double _threatIntelScore;
        private double _correlationScore;

        public ConfidenceBuilder AddEvidence(double amount, string reason) { _evidenceScore += amount; AddReason(reason); return this; }
        public ConfidenceBuilder AddBaseline(double amount, string reason) { _baselineScore += amount; AddReason(reason); return this; }
        public ConfidenceBuilder AddThreatIntel(double amount, string reason) { _threatIntelScore += amount; AddReason(reason); return this; }
        public ConfidenceBuilder AddCorrelation(double amount, string reason) { _correlationScore += amount; AddReason(reason); return this; }

        public void ApplyTo(DetectionEvent evt)
        {
            if (evt == null) return;
            evt.EvidenceScore = Clamp(_evidenceScore);
            evt.BaselineScore = Clamp(_baselineScore);
            evt.ThreatIntelScore = Clamp(_threatIntelScore);
            evt.CorrelationScore = Clamp(_correlationScore);
            evt.ConfidenceScore = Clamp(_evidenceScore + _baselineScore + _threatIntelScore + _correlationScore);
            evt.ConfidenceLabel = Label(evt.ConfidenceScore);
            if (_reasons.Count > 0)
            {
                var summary = "confidence=" + evt.ConfidenceScore.ToString("0.00") + " (" + string.Join("; ", _reasons.Take(6)) + ")";
                if (evt.StructuredEvidence == null)
                {
                    evt.StructuredEvidence = new DetectionEvidenceSet(new[] { new DetectionEvidenceItem("confidence", summary, "confidence") }, evt.Evidence ?? evt.Description ?? summary);
                }
            }
        }

        public static void ApplyDefault(DetectionEvent evt, RuleDescriptor descriptor, RuleIntelligence intelligence)
        {
            if (evt == null) return;
            var builder = new ConfidenceBuilder();
            var sev = evt.Severity;
            builder.AddEvidence(sev switch
            {
                SeverityLevel.Critical => 0.75,
                SeverityLevel.High => 0.65,
                SeverityLevel.Medium => 0.50,
                SeverityLevel.Low => 0.35,
                _ => 0.25
            }, "severity-weight");

            if (!string.IsNullOrWhiteSpace(evt.Evidence)) builder.AddEvidence(0.10, "evidence-present");
            if (intelligence.SignalKind == RuleSignalKind.Baseline) builder.AddBaseline(0.10, "baseline-rule");
            if (intelligence.AttackTechniqueIds.Count > 0) builder.AddCorrelation(0.05, "mapped-technique");
            if (descriptor.RuleId is "R003" or "R016") builder.AddThreatIntel(0.20, "threat-intel-source");
            builder.ApplyTo(evt);
        }

        public static DetectionConfidenceLabel Label(double score)
        {
            if (score >= 0.75) return DetectionConfidenceLabel.High;
            if (score >= 0.45) return DetectionConfidenceLabel.Medium;
            if (score > 0.0) return DetectionConfidenceLabel.Low;
            return DetectionConfidenceLabel.Unknown;
        }

        private void AddReason(string reason)
        {
            if (!string.IsNullOrWhiteSpace(reason)) _reasons.Add(reason.Trim());
        }

        private static double Clamp(double value) => Math.Max(0.0, Math.Min(1.0, value));
    }
}
