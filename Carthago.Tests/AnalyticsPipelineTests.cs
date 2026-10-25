using Carthago.Analytics.Models;
using Carthago.Analytics.Services;
using Carthago.Models;
using System.IO;
using System.Text.Json;
using LiteDB;

namespace Carthago.Tests;

public sealed class AnalyticsPipelineTests
{
    [Fact]
    public void LocalStore_Incident_Save_Reports_Failure_When_Database_Is_Closed()
    {
        var path = Path.Combine(Path.GetTempPath(), "carthago-incident-failure-" + Guid.NewGuid().ToString("N") + ".db");
        var store = new LocalStore(path);
        store.Dispose();

        Assert.False(store.SaveIncident(new Incident { Id = "incident-closed", Title = "Unsaved event" }));
    }

    [Fact]
    public void AnalyticsHost_Reports_Incident_Save_Failure_To_Health_Counter()
    {
        var path = Path.Combine(Path.GetTempPath(), "carthago-incident-health-" + Guid.NewGuid().ToString("N") + ".db");
        var store = new LocalStore(path);
        Assert.True(store.SaveIncident(new Incident { Id = "incident-health", Title = "Existing incident" }));
        using var host = new Carthago.Analytics.AnalyticsHost(TimeSpan.FromMinutes(5), store);
        store.Dispose();

        host.UpdateIncidentStatus("incident-health", "Investigating");

        Assert.Equal(1, host.IncidentPersistenceFailures);
    }

    [Fact]
    public void LocalStore_Cannot_Preserve_Unreadable_Database_Does_Not_Delete_Its_Bytes()
    {
        var directory = Path.Combine(Path.GetTempPath(), "carthago-recovery-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, "analytics.db");
        var original = new byte[] { 0x43, 0x41, 0x52, 0x54, 0x48, 0x41, 0x47, 0x4F };
        File.WriteAllBytes(path, original);

        Assert.Throws<IOException>(() => LocalStore.PreserveCorruptDatabase(path,
            (_, _) => throw new IOException("simulated storage or file-lock failure")));

        Assert.Equal(original, File.ReadAllBytes(path));
        Assert.Single(Directory.GetFiles(directory));
    }

    [Fact]
    public void LocalStore_Updates_Existing_Legacy_Baseline_Without_Duplicate_HostId()
    {
        var path = Path.Combine(Path.GetTempPath(), "carthago-legacy-baseline-" + Guid.NewGuid().ToString("N") + ".db");
        const string host = "192.168.1.44";
        // Previous releases stored auto-generated document IDs rather than HostId as _id.
        using (var db = new LiteDatabase(path))
        {
            var collection = db.GetCollection("baseline_snapshots");
            collection.Insert(new BsonDocument { ["HostId"] = host, ["ObservationWindows"] = 1 });
        }

        using (var store = new LocalStore(path))
        {
            Assert.True(store.SaveBaselineSnapshots(new[] { new BaselineSnapshot { HostId = host, ObservationWindows = 3 } }));
            var snapshot = Assert.Single(store.LoadBaselineSnapshots());
            Assert.Equal(3, snapshot.ObservationWindows);
        }

        using var reopened = new LiteDatabase(path);
        Assert.Single(reopened.GetCollection("baseline_snapshots").FindAll());
    }

    [Fact]
    public void LocalStore_Returns_Failure_If_Baseline_Cannot_Be_Persisted()
    {
        var path = Path.Combine(Path.GetTempPath(), "carthago-baseline-failure-" + Guid.NewGuid().ToString("N") + ".db");
        var store = new LocalStore(path);
        store.Dispose();

        Assert.False(store.SaveBaselineSnapshots(new[] { new BaselineSnapshot { HostId = "10.0.0.42" } }));
    }

    [Fact]
    public void BaselineEngine_Emits_Explainable_Novelty_Anomalies()
    {
        var engine = new BaselineEngine(TimeSpan.FromMinutes(5));
        var start = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc);

        for (var i = 0; i < 5; i++)
        {
            engine.ObserveTraffic(new FlowFeature
            {
                TimestampUtc = start.AddMinutes(i * 5),
                SourceIp = "192.168.1.44",
                DestinationIp = "8.8.8.8",
                DestinationPort = 443,
                Protocol = "TCP",
                Bytes = 1200,
                IsInternalDestination = false
            });
        }

        var anomalies = engine.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(21),
            SourceIp = "192.168.1.44",
            DestinationIp = "1.1.1.1",
            DestinationPort = 8443,
            Protocol = "TCP",
            Bytes = 1600,
            IsInternalDestination = false
        });

        Assert.Contains(anomalies, signal => signal.Category == "DestinationNovelty");
        Assert.Contains(anomalies, signal => signal.Category == "PortNovelty");
        Assert.All(anomalies, signal => Assert.False(string.IsNullOrWhiteSpace(signal.Description)));
    }

    [Fact]
    public void IncidentCorrelationEngine_Deduplicates_Similar_Detections()
    {
        var engine = new IncidentCorrelationEngine(TimeSpan.FromMinutes(15));
        var first = new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 1, 12, 0, 0, DateTimeKind.Utc),
            RuleId = "R017",
            Description = "Port sweep detected",
            SourceIp = "10.0.0.10",
            DestinationIp = "203.0.113.40",
            DestinationPort = 22,
            Protocol = "TCP",
            Severity = SeverityLevel.Medium
        };
        var second = new DetectionEvent
        {
            Timestamp = first.Timestamp.AddSeconds(10),
            RuleId = "R017",
            Description = "Port sweep detected",
            SourceIp = "10.0.0.10",
            DestinationIp = "203.0.113.40",
            DestinationPort = 22,
            Protocol = "TCP",
            Severity = SeverityLevel.Medium
        };

        var result1 = engine.Correlate(first);
        var result2 = engine.Correlate(second);

        Assert.True(result1.IsNew);
        Assert.False(result2.IsNew);
        Assert.Single(engine.GetIncidents());
        Assert.Equal(2, engine.GetIncidents()[0].RelatedEvents.Count);
    }

    [Fact]
    public void RiskScoringEngine_Produces_Critical_Score_With_Reasons()
    {
        var incident = new Incident
        {
            Id = "inc-risk",
            Title = "Threat-linked outbound behavior",
            PrimarySourceIp = "192.168.1.44",
            Status = "New"
        };

        incident.RelatedEvents.Add(new DetectionEvent
        {
            Timestamp = DateTime.UtcNow,
            RuleId = "R023",
            Description = "Critical rule fired",
            SourceIp = "192.168.1.44",
            DestinationIp = "198.51.100.10",
            DestinationPort = 443,
            Protocol = "TCP",
            Severity = SeverityLevel.Critical
        });

        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "ThreatIntelMatch",
            Score = 0.92,
            Reasons = new List<string> { "Destination ASN not previously seen for this host" }
        });

        var scoring = new RiskScoringEngine();
        scoring.Score(incident);

        Assert.InRange(incident.RiskScore, 81, 100);
        Assert.Equal("Critical", incident.Severity);
        Assert.Contains(incident.RiskReasons, reason => reason.Contains("Critical rule matched", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(incident.RiskReasons, reason => reason.Contains("threat intelligence", StringComparison.OrdinalIgnoreCase));
    }

    [Theory]
    [InlineData("low", "Low")]
    [InlineData("medium", "Medium")]
    [InlineData("high", "High")]
    [InlineData("critical", "Critical")]
    public void RiskScoringEngine_Maps_Severity_Bands(string band, string expectedSeverity)
    {
        var incident = new Incident
        {
            Id = $"risk-{band}",
            Title = "Band mapping",
            Severity = "Low"
        };

        switch (band)
        {
            case "medium":
                incident.RelatedEvents.Add(new DetectionEvent
                {
                    Timestamp = DateTime.UtcNow,
                    RuleId = "R200",
                    Description = "Synthetic medium rule",
                    Severity = SeverityLevel.High
                });
                incident.RelatedAnomalies.Add(new AnomalySignal
                {
                    Category = "PortNovelty",
                    Score = 0.25
                });
                break;
            case "high":
                incident.RelatedEvents.Add(new DetectionEvent
                {
                    Timestamp = DateTime.UtcNow,
                    RuleId = "R201",
                    Description = "Synthetic high rule",
                    Severity = SeverityLevel.High
                });
                incident.RelatedAnomalies.Add(new AnomalySignal
                {
                    Category = "TrafficVolumeAnomaly",
                    Score = 0.6,
                    Reasons = new List<string> { "Outbound volume exceeded the learned baseline" }
                });
                incident.RelatedAnomalies.Add(new AnomalySignal
                {
                    Category = "ThreatIntelMatch",
                    Score = 0.4
                });
                break;
            case "critical":
                incident.RelatedEvents.Add(new DetectionEvent
                {
                    Timestamp = DateTime.UtcNow,
                    RuleId = "R202",
                    Description = "Synthetic critical rule",
                    Severity = SeverityLevel.Critical
                });
                incident.RelatedAnomalies.Add(new AnomalySignal
                {
                    Category = "ThreatIntelMatch",
                    Score = 0.95,
                    Reasons = new List<string> { "Destination ASN not previously seen for this host" }
                });
                break;
        }

        var scoring = new RiskScoringEngine();
        scoring.Score(incident);

        Assert.Equal(expectedSeverity, incident.Severity);
    }

    [Fact]
    public void FeatureExtractor_Does_Not_Crash_On_Missing_Fields()
    {
        var extractor = new FeatureExtractor();

        var traffic = extractor.FromTrafficRecord(new TrafficRecord
        {
            Source = "192.168.1.8"
        });

        var detection = extractor.FromDetectionEvent(new DetectionEvent
        {
            RuleId = "R001",
            Description = "desc"
        });

        Assert.Equal("192.168.1.8", traffic.SourceIp);
        Assert.True(traffic.TimestampUtc > DateTime.MinValue);
        Assert.Equal("R001", detection.RuleId);
        Assert.True(detection.TimestampUtc > DateTime.MinValue);
    }

    [Fact]
    public async Task LlmSummarizer_BackendNone_Uses_Fallback_Summary_And_Progress()
    {
        using var summarizer = new LlmSummarizer(LlmSummarizer.Backend.None);
        var progress = new List<string>();
        var incident = new Incident
        {
            Id = "inc-summary",
            Title = "Suspicious outbound behavior from 192.168.1.44",
            PrimarySourceIp = "192.168.1.44",
            PrimaryDestinationIp = "198.51.100.12",
            Evidence = new List<string> { "Outbound volume 6.2x above baseline" },
            RiskReasons = new List<string> { "Destination ASN not previously seen for this host" },
            RecommendedActions = new List<string> { "Inspect the responsible process" }
        };

        var summary = await summarizer.TrySummarizeAsync(incident, progress.Add);

        Assert.Contains("Suspicious outbound behavior", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Inspect the responsible process", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("started", progress);
        Assert.Contains("done", progress);
    }

    [Fact]
    public void IncidentCorrelationEngine_Groups_Related_Host_Compromise_Signals()
    {
        var engine = new IncidentCorrelationEngine(TimeSpan.FromMinutes(15));
        var ts = new DateTime(2026, 1, 7, 9, 31, 0, DateTimeKind.Utc);

        var dns = engine.Correlate(new AnomalySignal
        {
            Id = "a-dns",
            CreatedUtc = ts,
            UpdatedUtc = ts,
            SourceIp = "192.168.56.44",
            Category = "DnsAnomaly",
            Title = "DNS activity anomaly"
        });

        var asn = engine.Correlate(new AnomalySignal
        {
            Id = "a-asn",
            CreatedUtc = ts.AddMinutes(1),
            UpdatedUtc = ts.AddMinutes(1),
            SourceIp = "192.168.56.44",
            DestinationIp = "198.51.100.77",
            DestinationHost = "sync-demo.net",
            Category = "BehaviorChange",
            Title = "New ASN observed",
            Reasons = new List<string> { "Destination ASN AS65044 not previously seen for this host" }
        });

        var outbound = engine.Correlate(new DetectionEvent
        {
            Timestamp = ts.AddMinutes(2),
            RuleId = "R036",
            Description = "Pair exfiltration volume exceeded baseline",
            SourceIp = "192.168.56.44",
            DestinationIp = "198.51.100.77",
            DestinationHost = "sync-demo.net",
            DestinationPort = 8443,
            Protocol = "TCP",
            Severity = SeverityLevel.High
        });

        Assert.True(dns.IsNew);
        Assert.False(asn.IsNew);
        Assert.False(outbound.IsNew);
        Assert.Single(engine.GetIncidents());
        Assert.Equal(3, engine.GetIncidents()[0].OccurrenceCount);
    }

    [Fact]
    public async Task AnalyticsHost_DemoScenario_Creates_Single_HighRisk_Incident()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-analytics-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        using var host = new Carthago.Analytics.AnalyticsHost(
            TimeSpan.FromMinutes(5),
            store,
            llm: new LlmSummarizer(LlmSummarizer.Backend.None));

        var scenario = new AttackRunner().BuildCompromisedLaptopScenario();
        foreach (var record in scenario.TrafficRecords)
            host.OnTrafficRecord(record);

        foreach (var detection in scenario.DetectionEvents)
            host.OnDetection(detection);

        var timeoutAt = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < timeoutAt)
        {
            var incidents = host.GetRecentIncidents(10);
            if (incidents.Count > 0
                && incidents[0].RelatedEvents.Count >= 3
                && !string.IsNullOrWhiteSpace(incidents[0].Summary))
                break;

            await Task.Delay(100);
        }

        var incident = Assert.Single(host.GetRecentIncidents(10));
        Assert.Contains("Suspicious outbound behavior", incident.Title, StringComparison.OrdinalIgnoreCase);
        Assert.Equal("192.168.1.44", incident.PrimarySourceIp);
        Assert.True(incident.RiskScore >= 61);
        Assert.True(incident.RelatedEvents.Count >= 3);
        Assert.True(incident.RelatedAnomalies.Count >= 1);
        Assert.NotEmpty(incident.RecommendedActions);
        Assert.False(string.IsNullOrWhiteSpace(incident.Summary));
    }

    [Fact]
    public void DemoScenarioService_Builds_CompromisedLaptop_Package()
    {
        var package = new DemoScenarioService().BuildCompromisedLaptopScenario();

        Assert.Equal(DemoScenarioService.CompromisedLaptopScenarioName, package.Name);
        Assert.Equal("192.168.1.44", package.SourceIp);
        Assert.Equal($"Suspicious outbound behavior from {package.SourceIp}", package.ExpectedIncidentTitle);
        Assert.NotEmpty(package.TrafficRecords);
        Assert.Contains(package.AnomalySignals, signal => signal.Category == "DnsAnomaly");
        Assert.Contains(package.AnomalySignals, signal => signal.Category == "ThreatIntelMatch");
        Assert.All(package.AnomalySignals, signal => Assert.Contains(DemoScenarioService.DemoTag, signal.Tags));
    }

    [Fact]
    public async Task AnalyticsHost_ClearDemoData_Removes_Demo_Artifacts_Only()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-demo-clear-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        using var host = new Carthago.Analytics.AnalyticsHost(
            TimeSpan.FromMinutes(5),
            store,
            llm: new LlmSummarizer(LlmSummarizer.Backend.None));

        host.OnDetection(new DetectionEvent
        {
            Timestamp = DateTime.UtcNow,
            RuleId = "R017",
            Description = "Legitimate non-demo detection",
            SourceIp = "10.10.10.20",
            DestinationIp = "203.0.113.20",
            DestinationPort = 443,
            Protocol = "TCP",
            Severity = SeverityLevel.High
        });

        var demo = new DemoScenarioService().BuildCompromisedLaptopScenario();
        foreach (var anomaly in demo.AnomalySignals)
            host.OnAnomaly(anomaly, demo.ScenarioTag);
        foreach (var detection in demo.DetectionEvents)
            host.OnDetection(detection, demo.ScenarioTag);

        var timeoutAt = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < timeoutAt)
        {
            var incidentsSnapshot = host.GetRecentIncidents(20);
            var demoIncident = incidentsSnapshot.FirstOrDefault(incident =>
                incident.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase)));

            if (demoIncident != null && demoIncident.RelatedEvents.Count >= 4 && demoIncident.RelatedAnomalies.Count >= 5)
                break;

            await Task.Delay(100);
        }

        Assert.True(host.GetRecentIncidents(20).Count >= 2);

        host.ClearDemoData();

        var incidents = host.GetRecentIncidents(20);
        Assert.Single(incidents);
        Assert.DoesNotContain(incidents, incident => incident.Tags.Any(tag => string.Equals(tag, DemoScenarioService.DemoTag, StringComparison.OrdinalIgnoreCase)));
        Assert.Equal("10.10.10.20", incidents[0].PrimarySourceIp);
    }

    [Fact]
    public async Task LlmSummarizer_OllamaFailure_Falls_Back_Without_Throwing()
    {
        using var summarizer = new LlmSummarizer(
            LlmSummarizer.Backend.Ollama,
            baseUrl: "http://127.0.0.1:1",
            model: "missing-model",
            timeout: TimeSpan.FromMilliseconds(200));

        var incident = new Incident
        {
            Id = "inc-fallback",
            Title = "Suspicious outbound behavior from 192.168.1.44",
            PrimarySourceIp = "192.168.1.44",
            PrimaryDestinationIp = "198.51.100.12",
            Evidence = new List<string> { "Threat feed hit observed" },
            RecommendedActions = new List<string> { "Inspect the responsible process" }
        };

        var summary = await summarizer.TrySummarizeAsync(incident);

        Assert.Contains("Suspicious outbound behavior", summary, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("Inspect the responsible process", summary, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void LocalStore_Normalizes_Legacy_Null_Collections_On_Load()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-store-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        store.SaveIncident(new Incident
        {
            Id = "legacy-incident",
            Title = "Legacy",
            Severity = null!,
            Status = null!,
            RelatedEvents = null!,
            RelatedAnomalies = null!,
            Evidence = null!,
            RecommendedActions = null!,
            Tags = null!,
            RiskReasons = null!
        });

        var loaded = Assert.Single(store.LoadIncidents(10));
        Assert.Equal("Low", loaded.Severity);
        Assert.Equal("New", loaded.Status);
        Assert.NotNull(loaded.RelatedEvents);
        Assert.NotNull(loaded.RelatedAnomalies);
        Assert.NotNull(loaded.Evidence);
        Assert.NotNull(loaded.RecommendedActions);
    }

    [Fact]
    public void MlFeatureWindowBuilder_Groups_By_SourceHost_And_Window()
    {
        var builder = new MlFeatureWindowBuilder(TimeSpan.FromMinutes(5));
        var start = new DateTime(2026, 1, 7, 9, 0, 0, DateTimeKind.Utc);
        var completed = new List<MlFeatureWindow>();

        completed.AddRange(builder.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(1),
            SourceIp = "192.168.1.44",
            DestinationIp = "203.0.113.20",
            DestinationPort = 443,
            Direction = "outbound",
            Bytes = 1200
        }));

        completed.AddRange(builder.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(2),
            SourceIp = "192.168.1.44",
            DestinationIp = "203.0.113.21",
            DestinationPort = 443,
            Direction = "outbound",
            Bytes = 800
        }));

        completed.AddRange(builder.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(2),
            SourceIp = "192.168.1.60",
            DestinationIp = "203.0.113.90",
            DestinationPort = 80,
            Direction = "outbound",
            Bytes = 400
        }));

        completed.AddRange(builder.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(6),
            SourceIp = "192.168.1.44",
            DestinationIp = "203.0.113.20",
            DestinationPort = 443,
            Direction = "outbound",
            Bytes = 100
        }));

        completed.AddRange(builder.ObserveTraffic(new FlowFeature
        {
            TimestampUtc = start.AddMinutes(6),
            SourceIp = "192.168.1.60",
            DestinationIp = "203.0.113.90",
            DestinationPort = 80,
            Direction = "outbound",
            Bytes = 100
        }));

        Assert.Equal(2, completed.Count);
        Assert.Contains(completed, window => window.SourceIp == "192.168.1.44" && window.UniqueDestinationCount == 2);
        Assert.Contains(completed, window => window.SourceIp == "192.168.1.60" && window.UniqueDestinationCount == 1);
    }

    [Fact]
    public void MlAnomalyScoringEngine_Does_Not_Throw_On_Short_History()
    {
        var engine = new MlAnomalyScoringEngine();
        var start = new DateTime(2026, 1, 7, 9, 0, 0, DateTimeKind.Utc);

        for (var i = 0; i < 3; i++)
        {
            var score = engine.Evaluate(new MlFeatureWindow
            {
                SourceIp = "192.168.1.44",
                WindowStartUtc = start.AddMinutes(i * 5),
                WindowEndUtc = start.AddMinutes((i * 5) + 5),
                OutboundBytes = 1200,
                UniqueDestinationCount = 1
            });

            Assert.Null(score);
        }
    }

    [Fact]
    public void MlAnomalyScoringEngine_Does_Not_Return_NaN_Or_Infinity()
    {
        var engine = new MlAnomalyScoringEngine();
        var score = ScoreMlSpike(engine);

        Assert.NotNull(score);
        Assert.True(double.IsFinite(score!.Score));
        Assert.True(double.IsFinite(score.Confidence));
    }

    [Fact]
    public void MlAnomalyScoringEngine_Produces_Normalized_Score()
    {
        var engine = new MlAnomalyScoringEngine();
        var score = ScoreMlSpike(engine);

        Assert.NotNull(score);
        Assert.InRange(score!.Score, 0, 100);
        Assert.InRange(score.Confidence, 0, 1);
    }

    [Fact]
    public void MlAnomalySignal_Does_Not_Create_Critical_Incident_Alone()
    {
        var incident = new Incident
        {
            Id = "ml-only",
            Title = "ML-only behavior anomaly",
            PrimarySourceIp = "192.168.1.44"
        };

        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "MlBehaviorAnomaly",
            Score = 0.88,
            Features = new Dictionary<string, string> { ["MlScore"] = "88" },
            Reasons = new List<string> { "ML.NET detected an unusual spike in outbound bytes for this host." },
            Tags = new List<string> { "ml", "ml-assisted" }
        });

        new RiskScoringEngine().Score(incident);

        Assert.InRange(incident.RiskScore, 0, 60);
        Assert.NotEqual("Critical", incident.Severity);
    }

    [Fact]
    public async Task AnalyticsHost_DemoScenario_Can_Include_MlSignal_Without_Fragmenting_Incident()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-ml-demo-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        using var host = new Carthago.Analytics.AnalyticsHost(
            TimeSpan.FromMinutes(5),
            store,
            llm: new LlmSummarizer(LlmSummarizer.Backend.None));

        var demo = new DemoScenarioService().BuildCompromisedLaptopScenario();
        foreach (var record in demo.TrafficRecords)
            host.OnTrafficRecord(record, demo.ScenarioTag);
        foreach (var anomaly in demo.AnomalySignals)
            host.OnAnomaly(anomaly, demo.ScenarioTag);
        foreach (var detection in demo.DetectionEvents)
            host.OnDetection(detection, demo.ScenarioTag);

        var timeoutAt = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < timeoutAt)
        {
            var incidents = host.GetRecentIncidents(20)
                .Where(incident => incident.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase)))
                .ToList();

            if (incidents.Count == 1 && incidents[0].RelatedEvents.Count >= 4)
                break;

            await Task.Delay(100);
        }

        var incident = Assert.Single(host.GetRecentIncidents(20)
            .Where(entry => entry.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase))));
        Assert.True(incident.RelatedAnomalies.Count >= 5);

        var mlAnomaly = incident.RelatedAnomalies.FirstOrDefault(anomaly => anomaly.Category == "MlBehaviorAnomaly");
        if (mlAnomaly != null)
        {
            Assert.Contains(incident.RiskReasons, reason => reason.Contains("ML-assisted", StringComparison.OrdinalIgnoreCase));
        }
    }

    [Fact]
    public void RiskScoringEngine_MlSignal_Adds_Reason_But_Does_Not_Override_Deterministic_Evidence()
    {
        var incident = new Incident
        {
            Id = "ml-supporting",
            Title = "Supporting ML signal",
            PrimarySourceIp = "192.168.1.44"
        };

        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "PortNovelty",
            Score = 0.35,
            Reasons = new List<string> { "Destination port 8443 not previously seen for this host" }
        });
        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "MlBehaviorAnomaly",
            Score = 0.76,
            Features = new Dictionary<string, string> { ["MlScore"] = "76" },
            Reasons = new List<string> { "ML.NET detected unusual destination fan-out compared with recent host activity." },
            Tags = new List<string> { "ml", "ml-assisted" }
        });

        new RiskScoringEngine().Score(incident);

        Assert.Contains(incident.RiskReasons, reason => reason.Contains("ML-assisted anomaly score", StringComparison.OrdinalIgnoreCase));
        Assert.NotEqual("Critical", incident.Severity);
    }

    [Fact]
    public void IncidentFeedbackStore_Saves_And_Loads_Feedback()
    {
        var path = Path.Combine(Path.GetTempPath(), $"carthago-feedback-{Guid.NewGuid():N}.json");
        var store = new IncidentFeedbackStore(path);
        store.SaveFeedback(new IncidentFeedback
        {
            IncidentId = "incident-1",
            FeedbackType = "ExpectedBehavior",
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Category = "Behavior",
            AnalystNote = "Approved backup destination."
        });

        var reloaded = new IncidentFeedbackStore(path);
        var entry = Assert.Single(reloaded.GetAll());
        Assert.Equal("ExpectedBehavior", entry.FeedbackType);
        Assert.Equal("Approved backup destination.", entry.AnalystNote);
    }

    [Fact]
    public void RiskScoringEngine_ExpectedBehavior_Lowers_Similar_Risk()
    {
        var baseline = CreateDestinationNoveltyIncident();
        var scoring = new RiskScoringEngine();
        scoring.Score(baseline);

        var reduced = CreateDestinationNoveltyIncident();
        scoring.Score(reduced, new[]
        {
            new IncidentFeedback
            {
                FeedbackType = "ExpectedBehavior",
                SourceIp = reduced.PrimarySourceIp,
                DestinationHost = reduced.PrimaryDestinationHost,
                Category = reduced.Category
            }
        });

        Assert.True(reduced.RiskScore < baseline.RiskScore);
        Assert.Contains(reduced.RiskReasons, reason => reason.Contains("marked expected", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RiskScoringEngine_ConfirmedSuspicious_Increases_Similar_Risk()
    {
        var baseline = CreateDestinationNoveltyIncident();
        var scoring = new RiskScoringEngine();
        scoring.Score(baseline);

        var increased = CreateDestinationNoveltyIncident();
        scoring.Score(increased, new[]
        {
            new IncidentFeedback
            {
                FeedbackType = "ConfirmedSuspicious",
                SourceIp = increased.PrimarySourceIp,
                DestinationHost = increased.PrimaryDestinationHost,
                Category = increased.Category
            }
        });

        Assert.True(increased.RiskScore > baseline.RiskScore);
        Assert.Contains(increased.RiskReasons, reason => reason.Contains("confirmed suspicious", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void RiskScoringEngine_ThreatFeedHit_NotFullySuppressed()
    {
        var incident = CreateThreatIncident();
        var scoring = new RiskScoringEngine();
        scoring.Score(incident, new[]
        {
            new IncidentFeedback
            {
                FeedbackType = "SuppressSimilar",
                SourceIp = incident.PrimarySourceIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category,
                SuppressUntilUtc = DateTime.UtcNow.AddDays(7)
            }
        });

        Assert.True(incident.RiskScore >= 40);
        Assert.Contains(incident.RiskReasons, reason => reason.Contains("threat intelligence", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(incident.FeedbackAppliedReasons, reason => reason.Contains("suppression active", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void SuppressSimilar_Expires_After_Configured_Time()
    {
        var path = Path.Combine(Path.GetTempPath(), $"carthago-feedback-expire-{Guid.NewGuid():N}.json");
        var store = new IncidentFeedbackStore(path);
        var incident = CreateDestinationNoveltyIncident();

        store.SaveFeedback(new IncidentFeedback
        {
            FeedbackType = "SuppressSimilar",
            SourceIp = incident.PrimarySourceIp,
            DestinationHost = incident.PrimaryDestinationHost,
            Category = incident.Category,
            SuppressUntilUtc = DateTime.UtcNow.AddMinutes(-2)
        });

        var matching = store.GetMatchingFeedback(incident);
        Assert.Empty(matching);
    }

    [Fact]
    public void TrustDestinationForHost_Reduces_DestinationNovelty_Risk()
    {
        var baseline = CreateDestinationNoveltyIncident();
        var scoring = new RiskScoringEngine();
        scoring.Score(baseline);

        var reduced = CreateDestinationNoveltyIncident();
        scoring.Score(reduced, new[]
        {
            new IncidentFeedback
            {
                FeedbackType = "TrustDestinationForHost",
                SourceIp = reduced.PrimarySourceIp,
                DestinationHost = reduced.PrimaryDestinationHost,
                Category = reduced.Category
            }
        });

        Assert.True(reduced.RiskScore < baseline.RiskScore);
        Assert.Contains(reduced.FeedbackAppliedReasons, reason => reason.Contains("destination trusted", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void FalsePositive_Feedback_Adds_Explainable_RiskReason()
    {
        var incident = CreateDestinationNoveltyIncident();
        new RiskScoringEngine().Score(incident, new[]
        {
            new IncidentFeedback
            {
                FeedbackType = "FalsePositive",
                SourceIp = incident.PrimarySourceIp,
                DestinationHost = incident.PrimaryDestinationHost,
                Category = incident.Category
            }
        });

        Assert.Contains(incident.RiskReasons, reason => reason.Contains("false positive", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(incident.FeedbackAppliedReasons, reason => reason.Contains("false positive", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public async Task DemoScenario_Feedback_Reduces_RerunNoise()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-feedback-demo-{Guid.NewGuid():N}.db");
        var feedbackPath = Path.Combine(Path.GetTempPath(), $"carthago-feedback-demo-{Guid.NewGuid():N}.json");
        using var store = new LocalStore(dbPath);
        var feedbackStore = new IncidentFeedbackStore(feedbackPath);
        using var host = new Carthago.Analytics.AnalyticsHost(
            TimeSpan.FromMinutes(5),
            store,
            llm: new LlmSummarizer(LlmSummarizer.Backend.None),
            feedbackStore: feedbackStore);

        var demo = new DemoScenarioService().BuildCompromisedLaptopScenario();
        await RunDemoScenarioAsync(host, demo);
        var firstIncident = Assert.Single(host.GetRecentIncidents(20)
            .Where(entry => entry.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase))));

        host.MarkIncidentExpected(firstIncident.Id, "Expected for test rerun.");
        host.ClearDemoData(includeFeedback: false);

        await RunDemoScenarioAsync(host, demo);
        var secondIncident = Assert.Single(host.GetRecentIncidents(20)
            .Where(entry => entry.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase))));

        Assert.True(secondIncident.RiskScore < firstIncident.RiskScore);
        Assert.Contains(secondIncident.FeedbackAppliedReasons, reason => reason.Contains("marked expected", StringComparison.OrdinalIgnoreCase));
    }

    [Fact]
    public void CorruptFeedbackStore_Does_Not_Crash()
    {
        var path = Path.Combine(Path.GetTempPath(), $"carthago-feedback-corrupt-{Guid.NewGuid():N}.json");
        File.WriteAllText(path, "{ definitely-not-json");

        var store = new IncidentFeedbackStore(path);
        Assert.Empty(store.GetAll());
    }

    [Fact]
    public void IncidentTimelineBuilder_Creates_Detection_And_Anomaly_Items()
    {
        var builder = new IncidentTimelineBuilder();
        var incident = new Incident
        {
            Id = "timeline-1",
            PrimarySourceIp = "192.168.1.44",
            PrimaryDestinationHost = "sync-demo.net",
            Category = "Behavior"
        };

        builder.AddDetection(incident, new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 7, 9, 31, 0, DateTimeKind.Utc),
            RuleId = "R006",
            Description = "Possible DNS tunneling from compromised laptop",
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Severity = SeverityLevel.High
        });
        builder.AddAnomaly(incident, new AnomalySignal
        {
            Id = "anomaly-1",
            CreatedUtc = new DateTime(2026, 1, 7, 9, 32, 0, DateTimeKind.Utc),
            UpdatedUtc = new DateTime(2026, 1, 7, 9, 32, 0, DateTimeKind.Utc),
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Category = "DestinationNovelty",
            Title = "New external destination contacted",
            Description = "The destination has not previously been observed for this host."
        });

        Assert.Contains(incident.TimelineItems, item => item.Type == "Detection");
        Assert.Contains(incident.TimelineItems, item => item.Type == "Anomaly");
    }

    [Fact]
    public void IncidentTimelineBuilder_Sorts_By_Timestamp()
    {
        var builder = new IncidentTimelineBuilder();
        var incident = new Incident { Id = "timeline-sort" };

        builder.AddAnomaly(incident, new AnomalySignal
        {
            Id = "late",
            CreatedUtc = new DateTime(2026, 1, 7, 9, 35, 0, DateTimeKind.Utc),
            UpdatedUtc = new DateTime(2026, 1, 7, 9, 35, 0, DateTimeKind.Utc),
            SourceIp = "192.168.1.44",
            Category = "TrafficVolumeAnomaly",
            Title = "Outbound traffic spike"
        });
        builder.AddDetection(incident, new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 7, 9, 31, 0, DateTimeKind.Utc),
            RuleId = "R006",
            Description = "DNS spike"
        });

        Assert.True(incident.TimelineItems[0].TimestampUtc <= incident.TimelineItems[1].TimestampUtc);
    }

    [Fact]
    public void IncidentTimelineBuilder_Deduplicates_Repeated_Items()
    {
        var builder = new IncidentTimelineBuilder();
        var incident = new Incident { Id = "timeline-dedupe" };
        var evt = new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 7, 9, 31, 0, DateTimeKind.Utc),
            RuleId = "R006",
            Description = "DNS spike"
        };

        builder.AddDetection(incident, evt);
        builder.AddDetection(incident, evt);

        Assert.Single(incident.TimelineItems);
    }

    [Fact]
    public void IncidentTimelineBuilder_Adds_RiskChange_When_Score_Changes()
    {
        var builder = new IncidentTimelineBuilder();
        var incident = new Incident
        {
            Id = "timeline-risk",
            RiskScore = 74,
            Severity = "High",
            UpdatedUtc = new DateTime(2026, 1, 7, 9, 35, 0, DateTimeKind.Utc)
        };

        builder.AddRiskChange(incident, 48, "Medium", "Risk increased after multiple related anomalies were correlated.");

        var item = Assert.Single(incident.TimelineItems);
        Assert.Equal("RiskChange", item.Type);
        Assert.Equal(74, item.RiskScoreAfter);
    }

    [Fact]
    public void IncidentTimelineBuilder_Adds_Feedback_Item()
    {
        var builder = new IncidentTimelineBuilder();
        var incident = new Incident { Id = "timeline-feedback" };
        var feedback = new IncidentFeedback
        {
            IncidentId = incident.Id,
            FeedbackType = "ExpectedBehavior",
            CreatedUtc = new DateTime(2026, 1, 7, 9, 40, 0, DateTimeKind.Utc),
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Category = "Behavior"
        };

        builder.AddFeedback(incident, feedback, new[] { "Risk reduced: similar behavior marked expected by analyst." });

        var item = Assert.Single(incident.TimelineItems);
        Assert.Equal("Feedback", item.Type);
        Assert.Contains("expected", item.Description, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void IncidentCorrelation_Updates_Timeline_Without_Fragmenting_Incident()
    {
        var builder = new IncidentTimelineBuilder();
        var engine = new IncidentCorrelationEngine(TimeSpan.FromMinutes(15), timelineBuilder: builder);
        var ts = new DateTime(2026, 1, 7, 9, 31, 0, DateTimeKind.Utc);

        var first = engine.Correlate(new DetectionEvent
        {
            Timestamp = ts,
            RuleId = "R006",
            Description = "DNS spike",
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Severity = SeverityLevel.High
        });

        var second = engine.Correlate(new AnomalySignal
        {
            Id = "timeline-anomaly",
            CreatedUtc = ts.AddMinutes(1),
            UpdatedUtc = ts.AddMinutes(1),
            SourceIp = "192.168.1.44",
            DestinationHost = "sync-demo.net",
            Category = "DestinationNovelty",
            Title = "New external destination contacted"
        });

        Assert.True(first.IsNew);
        Assert.False(second.IsNew);
        Assert.Single(engine.GetIncidents());
        Assert.True(engine.GetIncidents()[0].TimelineItems.Count >= 2);
    }

    [Fact]
    public async Task DemoScenario_Creates_Clear_Timeline()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-timeline-demo-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        using var host = new Carthago.Analytics.AnalyticsHost(
            TimeSpan.FromMinutes(5),
            store,
            llm: new LlmSummarizer(LlmSummarizer.Backend.None));

        var demo = new DemoScenarioService().BuildCompromisedLaptopScenario();
        await RunDemoScenarioAsync(host, demo);

        var incident = Assert.Single(host.GetRecentIncidents(20)
            .Where(entry => entry.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase))));

        Assert.NotEmpty(incident.TimelineItems);
        Assert.Contains(incident.TimelineItems, item => item.Type == "Detection");
        Assert.Contains(incident.TimelineItems, item => item.Type == "Anomaly" || item.Type == "MlSignal");
        Assert.Contains(incident.TimelineItems, item => item.Type == "RiskChange");
    }

    [Fact]
    public void MarkdownExport_Includes_Timeline()
    {
        var incident = CreateDestinationNoveltyIncident();
        incident.TimelineItems.Add(new IncidentTimelineItem
        {
            Id = "timeline-export",
            TimestampUtc = new DateTime(2026, 1, 7, 9, 32, 0, DateTimeKind.Utc),
            Type = "Anomaly",
            Title = "New external destination contacted",
            Description = "The destination has not previously been observed for this host."
        });

        var markdown = Carthago.Views.IncidentVm.From(incident).ToMarkdown();

        Assert.Contains("## Timeline", markdown, StringComparison.OrdinalIgnoreCase);
        Assert.Contains("New external destination contacted", markdown, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public void OldIncident_WithoutTimeline_Loads_Safely()
    {
        var dbPath = Path.Combine(Path.GetTempPath(), $"carthago-old-timeline-{Guid.NewGuid():N}.db");
        using var store = new LocalStore(dbPath);
        store.SaveIncident(new Incident
        {
            Id = "legacy-no-timeline",
            Title = "Legacy incident",
            TimelineItems = null!
        });

        var loaded = Assert.Single(store.LoadIncidents(10));
        Assert.NotNull(loaded.TimelineItems);
        Assert.Empty(loaded.TimelineItems);
    }

    private static MlAnomalyScore? ScoreMlSpike(MlAnomalyScoringEngine engine)
    {
        var start = new DateTime(2026, 1, 7, 9, 0, 0, DateTimeKind.Utc);
        MlAnomalyScore? score = null;

        for (var i = 0; i < 6; i++)
        {
            score = engine.Evaluate(new MlFeatureWindow
            {
                SourceIp = "192.168.1.44",
                WindowStartUtc = start.AddMinutes(i * 5),
                WindowEndUtc = start.AddMinutes((i * 5) + 5),
                OutboundBytes = 1200,
                UniqueDestinationCount = 1,
                RuleHitCount = 0,
                SeverityWeightedRuleCount = 0
            });
        }

        score = engine.Evaluate(new MlFeatureWindow
        {
            SourceIp = "192.168.1.44",
            WindowStartUtc = start.AddMinutes(30),
            WindowEndUtc = start.AddMinutes(35),
            OutboundBytes = 50000,
            UniqueDestinationCount = 14,
            RuleHitCount = 9,
            SeverityWeightedRuleCount = 18,
            NewDestinationCount = 10,
            ThreatIntelHitCount = 1
        });

        return score;
    }

    private static Incident CreateDestinationNoveltyIncident()
    {
        var incident = new Incident
        {
            Id = Guid.NewGuid().ToString("N"),
            Title = "Suspicious outbound behavior from 192.168.1.44",
            PrimarySourceIp = "192.168.1.44",
            PrimaryDestinationHost = "sync-demo.net",
            Category = "Behavior"
        };

        incident.RelatedEvents.Add(new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 7, 9, 32, 0, DateTimeKind.Utc),
            RuleId = "R024",
            Description = "Rare TLS fingerprint observed",
            SourceIp = "192.168.1.44",
            DestinationIp = "198.51.100.77",
            DestinationHost = "sync-demo.net",
            DestinationPort = 8443,
            Protocol = "TCP",
            ProcessName = "unknown.exe",
            Severity = SeverityLevel.Medium
        });

        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "DestinationNovelty",
            Title = "New external destination contacted",
            Score = 0.62,
            DestinationHost = "sync-demo.net",
            Reasons = new List<string> { "Destination was not previously seen for this host" }
        });
        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "PortNovelty",
            Title = "New destination port",
            Score = 0.55,
            DestinationPort = "8443",
            Reasons = new List<string> { "Destination port 8443 not previously seen for this host" }
        });

        return incident;
    }

    private static Incident CreateThreatIncident()
    {
        var incident = CreateDestinationNoveltyIncident();
        incident.RelatedEvents.Add(new DetectionEvent
        {
            Timestamp = new DateTime(2026, 1, 7, 9, 33, 0, DateTimeKind.Utc),
            RuleId = "R016",
            Description = "Threat feed hit",
            SourceIp = incident.PrimarySourceIp,
            DestinationHost = incident.PrimaryDestinationHost,
            Severity = SeverityLevel.Critical
        });
        incident.RelatedAnomalies.Add(new AnomalySignal
        {
            Category = "ThreatIntelMatch",
            Title = "Threat intelligence match",
            Score = 0.93,
            Reasons = new List<string> { "Threat-feed match observed" }
        });
        return incident;
    }

    private static async Task RunDemoScenarioAsync(Carthago.Analytics.AnalyticsHost host, DemoIncidentPackage demo)
    {
        foreach (var record in demo.TrafficRecords)
            host.OnTrafficRecord(record, demo.ScenarioTag);
        foreach (var anomaly in demo.AnomalySignals)
            host.OnAnomaly(anomaly, demo.ScenarioTag);
        foreach (var detection in demo.DetectionEvents)
            host.OnDetection(detection, demo.ScenarioTag);

        var timeoutAt = DateTime.UtcNow.AddSeconds(5);
        while (DateTime.UtcNow < timeoutAt)
        {
            var incident = host.GetRecentIncidents(20)
                .FirstOrDefault(entry => entry.Tags.Any(tag => string.Equals(tag, demo.ScenarioTag, StringComparison.OrdinalIgnoreCase)));
            if (incident != null && incident.RelatedEvents.Count >= 4)
                break;

            await Task.Delay(100);
        }
    }
}
