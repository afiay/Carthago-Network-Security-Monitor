// SPDX-License-Identifier: MIT
using System;
using System.Collections.Generic;
using System.Linq;
using Carthago.Analytics.Models;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    public sealed class DemoScenarioService
    {
        public const string DemoTag = "demo";
        public const string CompromisedLaptopScenarioTag = "demo:compromised-laptop";
        public const string CompromisedLaptopScenarioName = "Compromised Laptop - Suspicious Outbound Behavior";

        private readonly AttackRunner _attackRunner = new();

        public DemoIncidentPackage BuildCompromisedLaptopScenario()
        {
            const string sourceIp = "192.168.1.44";
            var scenario = _attackRunner.BuildCompromisedLaptopScenario(sourceIp);
            var firstSeenUtc = scenario.DetectionEvents.FirstOrDefault()?.Timestamp ?? DateTime.UtcNow;

            var anomalies = new List<AnomalySignal>
            {
                CreateAnomaly(
                    idSuffix: "dns",
                    createdUtc: firstSeenUtc,
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "jk3s9ab2nq-stage.sync-demo.net",
                    destinationPort: "53",
                    protocol: "DNS",
                    category: "DnsAnomaly",
                    title: $"DNS activity anomaly from {sourceIp}",
                    description: "DNS query volume exceeded the learned baseline for this host.",
                    severity: "high",
                    score: 0.82,
                    reasons: new[]
                    {
                        "DNS query volume exceeded baseline",
                        "Queried domain pattern is unusual for this host"
                    },
                    features: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProcessName"] = "unknown.exe",
                        ["Domain"] = "jk3s9ab2nq-stage.sync-demo.net",
                        ["Country"] = "NL",
                        ["Asn"] = "AS65044"
                    }),
                CreateAnomaly(
                    idSuffix: "dest",
                    createdUtc: firstSeenUtc.AddSeconds(30),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "DestinationNovelty",
                    title: $"New external destination contacted by {sourceIp}",
                    description: "The destination has not previously been observed for this host.",
                    severity: "medium",
                    score: 0.62,
                    reasons: new[]
                    {
                        "Destination was not previously seen for this host",
                        "Multiple related detections occurred within a short window"
                    },
                    features: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["ProcessName"] = "unknown.exe",
                        ["Domain"] = "sync-demo.net",
                        ["Country"] = "NL",
                        ["Asn"] = "AS65044"
                    }),
                CreateAnomaly(
                    idSuffix: "geo",
                    createdUtc: firstSeenUtc.AddMinutes(1),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "GeoAnomaly",
                    title: $"New country observed for {sourceIp}",
                    description: "The destination ASN and country are new for this host baseline.",
                    severity: "medium",
                    score: 0.58,
                    reasons: new[]
                    {
                        "Destination ASN/country is new for this host",
                        "The host has not previously contacted NL / AS65044"
                    },
                    features: new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    {
                        ["Country"] = "NL",
                        ["Asn"] = "AS65044"
                    }),
                CreateAnomaly(
                    idSuffix: "port",
                    createdUtc: firstSeenUtc.AddMinutes(1).AddSeconds(20),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "PortNovelty",
                    title: $"New destination port for {sourceIp}",
                    description: "An unusual destination port was observed for this host.",
                    severity: "medium",
                    score: 0.55,
                    reasons: new[]
                    {
                        "Unusual destination port observed",
                        "Port 8443 is not part of the host's normal outbound pattern"
                    }),
                CreateAnomaly(
                    idSuffix: "volume",
                    createdUtc: firstSeenUtc.AddMinutes(2),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "TrafficVolumeAnomaly",
                    title: $"Outbound traffic spike from {sourceIp}",
                    description: "Outbound volume exceeded baseline during the suspicious window.",
                    severity: "high",
                    score: 0.88,
                    reasons: new[]
                    {
                        "Outbound volume exceeded baseline",
                        "Large transfer concentrated to one new external destination"
                    }),
                CreateAnomaly(
                    idSuffix: "behavior",
                    createdUtc: firstSeenUtc.AddMinutes(2).AddSeconds(30),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "SuspiciousOutboundBehavior",
                    title: $"Suspicious outbound behavior from {sourceIp}",
                    description: "Multiple related anomalies and detections indicate suspicious outbound behavior from the host.",
                    severity: "high",
                    score: 0.91,
                    reasons: new[]
                    {
                        "Multiple related detections occurred within a short window",
                        "Destination, geography, port, and outbound volume all changed together"
                    }),
                CreateAnomaly(
                    idSuffix: "threat",
                    createdUtc: firstSeenUtc.AddMinutes(3),
                    sourceIp: sourceIp,
                    destinationIp: "198.51.100.77",
                    destinationHost: "sync-demo.net",
                    destinationPort: "8443",
                    protocol: "TCP",
                    category: "ThreatIntelMatch",
                    title: $"Threat intelligence match for {sourceIp}",
                    description: "The destination was flagged by the configured reputation source.",
                    severity: "high",
                    score: 0.93,
                    reasons: new[]
                    {
                        "Threat-feed or reputation source flagged the destination",
                        "The destination is unexplained for this host"
                    })
            };

            return new DemoIncidentPackage(
                Name: CompromisedLaptopScenarioName,
                ScenarioTag: CompromisedLaptopScenarioTag,
                ExpectedIncidentTitle: $"Suspicious outbound behavior from {sourceIp}",
                ExpectedIncidentCategory: "SuspiciousOutboundBehavior",
                SourceIp: sourceIp,
                TrafficRecords: scenario.TrafficRecords,
                DetectionEvents: scenario.DetectionEvents,
                AnomalySignals: anomalies);
        }

        private static AnomalySignal CreateAnomaly(
            string idSuffix,
            DateTime createdUtc,
            string sourceIp,
            string destinationIp,
            string destinationHost,
            string destinationPort,
            string protocol,
            string category,
            string title,
            string description,
            string severity,
            double score,
            IEnumerable<string> reasons,
            IDictionary<string, string>? features = null)
        {
            return new AnomalySignal
            {
                Id = $"{CompromisedLaptopScenarioTag}:{idSuffix}",
                CreatedUtc = createdUtc,
                UpdatedUtc = createdUtc,
                SourceIp = sourceIp,
                DestinationIp = destinationIp,
                DestinationHost = destinationHost,
                DestinationPort = destinationPort,
                Protocol = protocol,
                Category = category,
                Title = title,
                Description = description,
                Score = score,
                Severity = severity,
                Reasons = reasons.Where(value => !string.IsNullOrWhiteSpace(value)).ToList(),
                RelatedRuleIds = new List<string>(),
                Tags = new List<string> { DemoTag, CompromisedLaptopScenarioTag, "demo:security-monitor" },
                Features = features == null
                    ? new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase)
                    : new Dictionary<string, string>(features, StringComparer.OrdinalIgnoreCase)
            };
        }
    }

    public sealed record DemoIncidentPackage(
        string Name,
        string ScenarioTag,
        string ExpectedIncidentTitle,
        string ExpectedIncidentCategory,
        string SourceIp,
        IReadOnlyList<TrafficRecord> TrafficRecords,
        IReadOnlyList<DetectionEvent> DetectionEvents,
        IReadOnlyList<AnomalySignal> AnomalySignals);
}
