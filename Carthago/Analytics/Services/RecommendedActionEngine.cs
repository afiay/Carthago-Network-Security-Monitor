// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;

namespace Carthago.Analytics.Services
{
    public sealed class RecommendedActionEngine
    {
        public IReadOnlyList<string> GetActions(Incident incident)
        {
            if (incident == null) throw new ArgumentNullException(nameof(incident));

            var actions = new List<string>();
            var categories = incident.RelatedAnomalies.Select(a => a.Category).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var rules = incident.RelatedEvents.Select(e => e.RuleId).ToHashSet(StringComparer.OrdinalIgnoreCase);
            var descriptions = incident.RelatedEvents
                .Select(e => e.Description)
                .Where(text => !string.IsNullOrWhiteSpace(text))
                .ToArray();

            if (categories.Contains("DnsAnomaly") || rules.Contains("R006") || rules.Contains("R022") || rules.Contains("R034") || rules.Contains("R048"))
            {
                Add(actions, "Review queried domains and compare them with the host's normal DNS behavior.");
                Add(actions, "Check the process responsible for the DNS traffic.");
                Add(actions, "Confirm whether encrypted DNS or alternate resolver usage is expected.");
            }

            if (categories.Contains("TrafficVolumeAnomaly") || rules.Contains("R008") || rules.Contains("R036"))
            {
                Add(actions, "Confirm whether the transfer volume is expected for this host.");
                Add(actions, "Inspect the destination ASN and country for the affected flow.");
                Add(actions, "Validate whether the responsible process is trusted.");
                Add(actions, "Consider temporary isolation if the transfer is unexplained.");
            }

            if (categories.Contains("ThreatIntelMatch") || categories.Contains("ReputationHit") || rules.Contains("R003") || rules.Contains("R016"))
            {
                Add(actions, "Verify the threat feed or reputation source that triggered the incident.");
                Add(actions, "Validate whether the destination has any legitimate business use before containment.");
                Add(actions, "Search for related activity from the same host.");
            }

            if (categories.Contains("FingerprintNovelty") || rules.Contains("R024") || rules.Contains("R035") || rules.Contains("R037"))
            {
                Add(actions, "Review SNI, certificate, and JA4 or HASSH metadata for the connection.");
                Add(actions, "Compare the encrypted fingerprint with previous behavior for this host.");
                Add(actions, "Check destination reputation and ASN before taking containment action.");
            }

            if (categories.Contains("GeoAnomaly") || rules.Contains("R010") || rules.Contains("R039"))
            {
                Add(actions, "Confirm whether the new country or ASN is expected for this host.");
                Add(actions, "Review change windows, VPN usage, or admin activity that could explain the destination.");
            }

            if (rules.Contains("R001") || rules.Contains("R017") || rules.Contains("R030"))
            {
                Add(actions, "Review the target set and port pattern to confirm whether this is expected scanning activity.");
                Add(actions, "Identify the process or tool responsible for the sweep.");
            }

            if (descriptions.Any(text => text.Contains("failed", StringComparison.OrdinalIgnoreCase)
                                         || text.Contains("brute", StringComparison.OrdinalIgnoreCase)
                                         || text.Contains("authentication", StringComparison.OrdinalIgnoreCase)))
            {
                Add(actions, "Review authentication failures and confirm whether the source host or account recently changed behavior.");
                Add(actions, "Check whether the failures align with administrative activity, scheduled jobs, or password rotation.");
            }

            if (categories.Contains("PortNovelty") || categories.Contains("ProcessNetworkAnomaly"))
            {
                Add(actions, "Confirm whether the destination port and originating process are expected for this host.");
                Add(actions, "Review recent change windows before suppressing or allowlisting the behavior.");
            }

            if (incident.Category.Contains("Exfiltration", StringComparison.OrdinalIgnoreCase)
                || categories.Contains("TrafficVolumeAnomaly")
                || categories.Contains("DestinationNovelty")
                || categories.Contains("GeoAnomaly"))
            {
                Add(actions, "Inspect the destination, transfer timing, and business context to determine whether the outbound behavior is expected.");
                Add(actions, "Review surrounding raw traffic and detections to see whether this host is contacting additional new destinations.");
            }

            if (incident.Category.Contains("Cisco", StringComparison.OrdinalIgnoreCase))
            {
                Add(actions, "Check the affected Cisco device and review system and interface logs.");
                Add(actions, "Verify whether a configuration change or maintenance window occurred recently.");
                Add(actions, "Confirm whether adjacent devices or peers reported the same condition during the same time window.");
            }

            if (actions.Count == 0)
            {
                Add(actions, "Review the host, process, and destination involved in this incident.");
                Add(actions, "Confirm whether the behavior is expected for the affected system.");
                Add(actions, "Collect supporting endpoint and network telemetry before containment.");
            }

            return actions.Take(5).ToArray();
        }

        private static void Add(List<string> actions, string action)
        {
            if (actions.Any(existing => string.Equals(existing, action, StringComparison.OrdinalIgnoreCase)))
                return;
            actions.Add(action);
        }
    }
}
