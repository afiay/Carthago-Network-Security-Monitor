// SPDX-License-Identifier: MIT
// File: Engine/Rules/Abstractions/EvidenceBuilder.cs
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Models;

namespace Carthago.Engine.Rules
{
    public static class EvidenceBuilder
    {
        public static DetectionEvidenceSet FromLegacyEvidence(string? summary, string? evidence, params DetectionEvidenceItem[] additional)
        {
            var items = new List<DetectionEvidenceItem>();
            if (!string.IsNullOrWhiteSpace(evidence))
            {
                foreach (var part in evidence.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Take(20))
                {
                    var idx = part.IndexOf('=');
                    if (idx > 0 && idx < part.Length - 1)
                        items.Add(new DetectionEvidenceItem(part[..idx].Trim(), part[(idx + 1)..].Trim(), "legacy-evidence"));
                    else
                        items.Add(new DetectionEvidenceItem("observed", part, "legacy-evidence"));
                }
            }
            items.AddRange(additional.Where(x => !string.IsNullOrWhiteSpace(x.Key) && !string.IsNullOrWhiteSpace(x.Value)));
            if (items.Count == 0 && !string.IsNullOrWhiteSpace(summary))
                items.Add(new DetectionEvidenceItem("summary", summary!, "rule"));
            return new DetectionEvidenceSet(items, summary ?? evidence ?? string.Empty);
        }

        public static void EnsureStructuredEvidence(DetectionEvent evt)
        {
            if (evt.StructuredEvidence != null && !string.IsNullOrWhiteSpace(evt.StructuredEvidence.Summary)) return;
            evt.StructuredEvidence = FromLegacyEvidence(evt.Summary, evt.Evidence);
        }

        public static void AppendEvidence(DetectionEvent evt, string key, string value, string source)
        {
            if (evt == null || string.IsNullOrWhiteSpace(key) || string.IsNullOrWhiteSpace(value))
                return;

            EnsureStructuredEvidence(evt);
            var items = evt.StructuredEvidence?.Items?.ToList() ?? new List<DetectionEvidenceItem>();
            items.Add(new DetectionEvidenceItem(key.Trim(), value.Trim(), source));
            evt.StructuredEvidence = new DetectionEvidenceSet(items, evt.StructuredEvidence?.Summary ?? evt.Summary ?? evt.Evidence ?? string.Empty);

            if (string.IsNullOrWhiteSpace(evt.Evidence))
                evt.Evidence = $"{key}={value}";
            else if (!evt.Evidence.Contains($"{key}={value}", StringComparison.OrdinalIgnoreCase))
                evt.Evidence += $"; {key}={value}";
        }
    }
}
