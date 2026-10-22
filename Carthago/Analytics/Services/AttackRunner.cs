// SPDX-License-Identifier: MIT
// File: Analytics/Services/AttackRunner.cs
using System;
using System.Collections.Generic;
using Carthago.Models;

namespace Carthago.Analytics.Services
{
    /// <summary>
    /// Developer-side deterministic demo data for validating anomaly-first behavior.
    /// This is not wired into production monitoring paths.
    /// </summary>
    public sealed class AttackRunner
    {
        public DemoScenario BuildCompromisedLaptopScenario(string sourceIp = "192.168.1.44")
        {
            var start = new DateTime(2026, 1, 7, 9, 0, 0, DateTimeKind.Utc);
            var traffic = new List<TrafficRecord>();
            var detections = new List<DetectionEvent>();

            for (var i = 0; i < 6; i++)
            {
                traffic.Add(new TrafficRecord
                {
                    Timestamp = start.AddMinutes(i * 5).ToString("o"),
                    Source = sourceIp,
                    Destination = "203.0.113.20",
                    DestinationPort = 443,
                    Protocol = "TCP",
                    Length = 1400,
                    ProcessName = "chrome.exe",
                    HttpHost = "portal.contoso.example",
                    DstCountryIso2 = "SE",
                    WhoisCountry = "SE",
                    WhoisASN = "AS64510",
                    Ja4 = "t13d1516h2_8daaf6152771_e5627efa2ab1"
                });
            }

            traffic.Add(new TrafficRecord
            {
                Timestamp = start.AddMinutes(31).ToString("o"),
                Source = sourceIp,
                Destination = "198.51.100.77",
                DestinationPort = 53,
                Protocol = "DNS",
                Length = 420,
                ProcessName = "unknown.exe",
                DnsQname = "jk3s9ab2nq-stage.sync-demo.net",
                DstCountryIso2 = "NL",
                WhoisCountry = "NL",
                WhoisASN = "AS65044"
            });

            traffic.Add(new TrafficRecord
            {
                Timestamp = start.AddMinutes(32).ToString("o"),
                Source = sourceIp,
                Destination = "198.51.100.77",
                DestinationPort = 8443,
                Protocol = "TCP",
                Length = 6200000,
                ProcessName = "unknown.exe",
                HttpHost = "sync-demo.net",
                DstCountryIso2 = "NL",
                WhoisCountry = "NL",
                WhoisASN = "AS65044",
                Ja4 = "t13d1516h2_demo_c2",
                ReputationIsMalicious = true,
                ReputationScore = 95
            });

            traffic.Add(new TrafficRecord
            {
                Timestamp = start.AddMinutes(36).ToString("o"),
                Source = sourceIp,
                Destination = "203.0.113.20",
                DestinationPort = 443,
                Protocol = "TCP",
                Length = 900,
                ProcessName = "chrome.exe",
                HttpHost = "portal.contoso.example",
                DstCountryIso2 = "SE",
                WhoisCountry = "SE",
                WhoisASN = "AS64510"
            });

            detections.Add(new DetectionEvent
            {
                Timestamp = start.AddMinutes(31),
                RuleId = "R006",
                Description = "Possible DNS tunneling from compromised laptop",
                SourceIp = sourceIp,
                DestinationIp = "198.51.100.77",
                DestinationHost = "jk3s9ab2nq-stage.sync-demo.net",
                DestinationPort = 53,
                Protocol = "DNS",
                ProcessName = "unknown.exe",
                Country = "NL",
                Asn = "AS65044",
                Severity = SeverityLevel.High,
                Count = 34,
                WindowSeconds = 30
            });

            detections.Add(new DetectionEvent
            {
                Timestamp = start.AddMinutes(32),
                RuleId = "R024",
                Description = "Rare TLS fingerprint observed",
                SourceIp = sourceIp,
                DestinationIp = "198.51.100.77",
                DestinationHost = "sync-demo.net",
                DestinationPort = 8443,
                Protocol = "TCP",
                ProcessName = "unknown.exe",
                Country = "NL",
                Asn = "AS65044",
                Ja4 = "t13d1516h2_demo_c2",
                Severity = SeverityLevel.Medium,
                Count = 1,
                WindowSeconds = 60
            });

            detections.Add(new DetectionEvent
            {
                Timestamp = start.AddMinutes(33),
                RuleId = "R016",
                Description = "AbuseIPDB score 95 ≥ 75",
                SourceIp = sourceIp,
                DestinationIp = "198.51.100.77",
                DestinationHost = "sync-demo.net",
                DestinationPort = 8443,
                Protocol = "TCP",
                ProcessName = "unknown.exe",
                Country = "NL",
                Asn = "AS65044",
                Severity = SeverityLevel.Critical,
                Count = 95,
                WindowSeconds = 60
            });

            detections.Add(new DetectionEvent
            {
                Timestamp = start.AddMinutes(34),
                RuleId = "R036",
                Description = "Pair exfiltration volume to single external destination exceeded baseline",
                SourceIp = sourceIp,
                DestinationIp = "198.51.100.77",
                DestinationHost = "sync-demo.net",
                DestinationPort = 8443,
                Protocol = "TCP",
                ProcessName = "unknown.exe",
                Country = "NL",
                Asn = "AS65044",
                Severity = SeverityLevel.High,
                Count = 1,
                WindowSeconds = 300
            });

            return new DemoScenario(traffic, detections);
        }
    }

    public sealed record DemoScenario(
        IReadOnlyList<TrafficRecord> TrafficRecords,
        IReadOnlyList<DetectionEvent> DetectionEvents);
}
