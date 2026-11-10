// SPDX-License-Identifier: MIT
// SOURCE CANDIDATE — UNVERIFIED. Read-only incident-to-detection navigation metadata.
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;

namespace Carthago.Views
{
    /// <summary>
    /// A recorded case reference, never an association inferred from IP, text or time.
    /// The target explorer independently checks its bounded retained-event snapshot.
    /// </summary>
    public sealed class IncidentDetectionLinkVm
    {
        private const int MaximumDisplayedLinks = 8;

        public string EventId { get; private init; } = string.Empty;
        public string RuleLabel { get; private init; } = "Rule not recorded";
        public string TimeLabel { get; private init; } = "Time not recorded";
        public string Description { get; private init; } = string.Empty;
        public bool CanInvestigate => EventId.Length is >= 1 and <= 128 && !EventId.Any(char.IsControl);
        public string EventIdLabel => CanInvestigate ? $"Event ID: {EventId}" : "Exact event ID unavailable";

        public static IReadOnlyList<IncidentDetectionLinkVm> FromIncident(Incident incident)
        {
            ArgumentNullException.ThrowIfNull(incident);
            var links = new List<IncidentDetectionLinkVm>(MaximumDisplayedLinks);
            var unlinkedDetections = new List<IncidentDetectionLinkVm>();
            var seenEventIds = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

            foreach (var evt in (incident.RelatedEvents ?? new()).OrderByDescending(item => item.Timestamp))
            {
                var id = NormalizeEventId(evt.EventId);
                if (id.Length > 0 && !seenEventIds.Add(id))
                    continue;

                var link = new IncidentDetectionLinkVm
                {
                    EventId = id,
                    RuleLabel = string.IsNullOrWhiteSpace(evt.RuleId) ? "Rule not recorded" : evt.RuleId,
                    TimeLabel = evt.Timestamp == default ? "Time not recorded" : evt.Timestamp.Kind == DateTimeKind.Unspecified
                        ? "Time zone not recorded"
                        : $"Local time: {evt.Timestamp.ToLocalTime():yyyy-MM-dd HH:mm:ss}",
                    Description = string.IsNullOrWhiteSpace(evt.Description) ? "Description not recorded." : evt.Description
                };
                if (id.Length == 0)
                {
                    // An unresolvable row must not consume the entire visible
                    // budget ahead of a real case-level EventId reference.
                    if (unlinkedDetections.Count < MaximumDisplayedLinks)
                        unlinkedDetections.Add(link);
                    continue;
                }

                links.Add(link);
                if (links.Count == MaximumDisplayedLinks)
                    return links;
            }

            // Persisted cases can retain an ID without embedding the original
            // DetectionEvent. Keep those valid IDs useful without inventing a row.
            foreach (var rawId in incident.RelatedEventIds ?? new())
            {
                var id = NormalizeEventId(rawId);
                if (id.Length == 0 || !seenEventIds.Add(id))
                    continue;

                links.Add(new IncidentDetectionLinkVm
                {
                    EventId = id,
                    Description = "Detection ID recorded; event details not attached to this case."
                });
                if (links.Count == MaximumDisplayedLinks)
                    break;
            }

            links.AddRange(unlinkedDetections.Take(MaximumDisplayedLinks - links.Count));

            return links;
        }

        private static string NormalizeEventId(string? value)
        {
            return IsExactEventId(value) ? value! : string.Empty;
        }

        internal static bool IsExactEventId(string? value)
        {
            // The explorer trims the event: argument. An ID requiring trim
            // would navigate to a different record, so it cannot be exact.
            return value is { Length: >= 1 and <= 128 } &&
                   string.Equals(value, value.Trim(), StringComparison.Ordinal) &&
                   !value.Any(char.IsControl);
        }
    }
}
