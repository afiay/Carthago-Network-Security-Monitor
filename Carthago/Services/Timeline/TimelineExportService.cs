// SPDX-License-Identifier: MIT
// File: Services/Timeline/TimelineExportService.cs
using System;
using System.Linq;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Carthago.Services.Timeline
{
    public sealed class TimelineExportService
    {
        private readonly JsonSerializerOptions _json = new() { WriteIndented = true, Converters = { new JsonStringEnumConverter() } };

        public string ExportJson(TimelineEvidenceBundle bundle, bool redactSensitive = true)
            => JsonSerializer.Serialize(Redact(bundle, redactSensitive), _json);

        public string ExportMarkdown(TimelineEvidenceBundle bundle, bool redactSensitive = true)
        {
            var b = Redact(bundle, redactSensitive);
            var sb = new StringBuilder();
            sb.AppendLine($"# Evidence Bundle {b.BundleId}");
            sb.AppendLine();
            sb.AppendLine($"Incident: {b.IncidentId}");
            sb.AppendLine($"Story: {b.StoryType}");
            sb.AppendLine($"Summary: {b.Summary}");
            sb.AppendLine();
            sb.AppendLine("## Timeline");
            foreach (var item in b.Timeline.OrderBy(i => i.TimestampUtc)) sb.AppendLine($"- {item.TimestampUtc:O} [{item.Type}] {item.Summary} ({item.EventId ?? item.EntityId ?? item.IncidentId})");
            return sb.ToString();
        }

        public string ExportCsv(TimelineEvidenceBundle bundle, bool redactSensitive = true)
        {
            var b = Redact(bundle, redactSensitive);
            var sb = new StringBuilder("timestamp,type,summary,event_id,incident_id,entity_id\n");
            foreach (var item in b.Timeline.OrderBy(i => i.TimestampUtc))
                sb.AppendLine($"{item.TimestampUtc:O},{Escape(item.Type)},{Escape(item.Summary)},{Escape(item.EventId)},{Escape(item.IncidentId)},{Escape(item.EntityId)}");
            return sb.ToString();
        }

        private static TimelineEvidenceBundle Redact(TimelineEvidenceBundle bundle, bool redactSensitive)
        {
            if (!redactSensitive) return bundle;
            var clone = JsonSerializer.Deserialize<TimelineEvidenceBundle>(JsonSerializer.Serialize(bundle)) ?? bundle;
            foreach (var evt in clone.Detections)
            {
                if (evt.StructuredEvidence == null) continue;
                evt.StructuredEvidence = evt.StructuredEvidence with
                {
                    Items = evt.StructuredEvidence.Items.Select(i => i.IsSensitive ? i with { Value = "[redacted]" } : i).ToList()
                };
            }
            return clone;
        }

        private static string Escape(string? s) => '"' + (s ?? string.Empty).Replace("\"", "\"\"") + '"';
    }
}
