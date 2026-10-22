// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
using System.Linq;
using Carthago.Analytics.Models;

namespace Carthago.Services
{
    public static class IncidentQueueProjectionService
    {
        public static IncidentQueueStats BuildStats(IEnumerable<Incident> incidents, DateTime utcNow)
        {
            var list = incidents?.ToArray() ?? Array.Empty<Incident>();
            var oneHourAgo = utcNow.AddHours(-1);

            return new IncidentQueueStats(
                ActiveIncidents: list.Count(incident => !IsResolved(incident)),
                CriticalIncidents: list.Count(incident => string.Equals(incident.Severity, "Critical", StringComparison.OrdinalIgnoreCase) && !IsResolved(incident)),
                NewInHour: list.Count(incident => incident.CreatedUtc >= oneHourAgo),
                InInvestigation: list.Count(incident => string.Equals(incident.Status, "Acknowledged", StringComparison.OrdinalIgnoreCase)
                                                     || string.Equals(incident.Status, "Investigating", StringComparison.OrdinalIgnoreCase)),
                ResolvedToday: list.Count(incident => IsResolved(incident) && incident.UpdatedUtc.ToLocalTime().Date == utcNow.ToLocalTime().Date));
        }

        public static IReadOnlyList<AffectedHostProjection> BuildAffectedHosts(Incident? selectedIncident, IEnumerable<Incident> incidents)
        {
            if (selectedIncident == null)
                return Array.Empty<AffectedHostProjection>();

            var relevantHosts = incidents?
                .Where(incident => !string.IsNullOrWhiteSpace(incident.PrimarySourceIp))
                .GroupBy(incident => incident.PrimarySourceIp!, StringComparer.OrdinalIgnoreCase)
                .Select(group => new AffectedHostProjection(
                    Host: group.Key,
                    Role: InferRole(group.Key),
                    RiskScore: group.Max(incident => incident.RiskScore),
                    IncidentCount: group.Count(),
                    TrendText: BuildTrendText(group),
                    Severity: group.OrderByDescending(incident => incident.RiskScore).First().Severity))
                .OrderByDescending(item => item.RiskScore)
                .ThenByDescending(item => item.IncidentCount)
                .Take(5)
                .ToArray()
                ?? Array.Empty<AffectedHostProjection>();

            if (relevantHosts.Length > 0)
                return relevantHosts;

            return new[]
            {
                new AffectedHostProjection(
                    Host: string.IsNullOrWhiteSpace(selectedIncident.PrimarySourceIp) ? "Unknown host" : selectedIncident.PrimarySourceIp!,
                    Role: "Workstation",
                    RiskScore: selectedIncident.RiskScore,
                    IncidentCount: Math.Max(1, selectedIncident.OccurrenceCount),
                    TrendText: "Single correlated incident",
                    Severity: selectedIncident.Severity)
            };
        }

        public static IReadOnlyList<ResponseChecklistProjection> BuildResponseChecklist(Incident? incident)
        {
            if (incident == null)
                return Array.Empty<ResponseChecklistProjection>();

            var actions = incident.RecommendedActions.Count == 0
                ? new[]
                {
                    "Validate incident context and scope.",
                    "Review related anomalies and detections.",
                    "Investigate source host activity.",
                    "Collect host artifacts and logs.",
                    "Document findings and resolution."
                }
                : incident.RecommendedActions.ToArray();

            var result = new List<ResponseChecklistProjection>(actions.Length);
            for (var i = 0; i < actions.Length; i++)
            {
                result.Add(new ResponseChecklistProjection(
                    Index: i + 1,
                    Title: actions[i],
                    Status: ResolveChecklistStatus(incident, i, actions.Length)));
            }

            return result;
        }

        public static int CountCompleted(IReadOnlyList<ResponseChecklistProjection> items)
            => items.Count(item => string.Equals(item.Status, "Done", StringComparison.OrdinalIgnoreCase));

        private static bool IsResolved(Incident incident)
            => string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase);

        private static string BuildTrendText(IGrouping<string, Incident> group)
        {
            var latest = group.OrderByDescending(incident => incident.UpdatedUtc).First();
            var previous = group
                .OrderByDescending(incident => incident.UpdatedUtc)
                .Skip(1)
                .FirstOrDefault();

            if (previous == null)
                return "First active pattern";

            var delta = latest.RiskScore - previous.RiskScore;
            if (delta == 0)
                return "Stable from previous incident";

            return delta > 0
                ? $"+{delta.ToString(CultureInfo.InvariantCulture)} vs previous"
                : $"{delta.ToString(CultureInfo.InvariantCulture)} vs previous";
        }

        private static string InferRole(string host)
        {
            if (host.Contains("dc", StringComparison.OrdinalIgnoreCase))
                return "Domain Controller";
            if (host.Contains("srv", StringComparison.OrdinalIgnoreCase) || host.Contains("server", StringComparison.OrdinalIgnoreCase))
                return "Server";
            if (host.Contains("gw", StringComparison.OrdinalIgnoreCase) || host.Contains("gateway", StringComparison.OrdinalIgnoreCase))
                return "Gateway";
            return "Workstation";
        }

        private static string ResolveChecklistStatus(Incident incident, int index, int total)
        {
            if (index == 0)
                return "Done";
            if (index == 1 && incident.RelatedAnomalies.Count > 0 && incident.RelatedEvents.Count > 0)
                return "Done";
            if (index == 2 && !string.Equals(incident.Status, "New", StringComparison.OrdinalIgnoreCase))
                return "In Progress";
            if (index == total - 1 && string.Equals(incident.Status, "Resolved", StringComparison.OrdinalIgnoreCase))
                return "Done";
            return "Pending";
        }
    }

    public sealed record IncidentQueueStats(
        int ActiveIncidents,
        int CriticalIncidents,
        int NewInHour,
        int InInvestigation,
        int ResolvedToday);

    public sealed record AffectedHostProjection(
        string Host,
        string Role,
        int RiskScore,
        int IncidentCount,
        string TrendText,
        string Severity);

    public sealed record ResponseChecklistProjection(
        int Index,
        string Title,
        string Status);
}
