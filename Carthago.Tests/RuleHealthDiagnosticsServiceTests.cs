using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
using Carthago.Services.Benchmarking;
using Carthago.Services.Diagnostics;
using Carthago.Services.Feedback;
using Xunit;

namespace Carthago.Tests
{
    public sealed class RuleHealthDiagnosticsServiceTests
    {
        [Fact]
        public async Task False_Positives_Reduce_Health_Score()
        {
            RuleRuntimeTelemetryStore.Reset();
            var root = CreateTempDirectory();
            var journalOptions = new DetectionJournalOptions { DirectoryPath = Path.Combine(root, "journal") };
            var feedbackStore = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback") });
            await WriteEventAsync(journalOptions, CreateEvent("R113", 0.72));
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R113", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.FalsePositive });
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R113", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.FalsePositive });

            RuleRuntimeTelemetryStore.RecordSelectorSelected("R113", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordEvaluated("R113", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordMatched("R113", DateTime.UtcNow, 0.72);

            var service = new RuleHealthDiagnosticsService(journalOptions, feedbackStore, benchmarkOutputDirectory: Path.Combine(root, "benchmark"));
            var diagnostic = (await service.SnapshotAsync()).Single(item => item.RuleId == "R113");

            Assert.True(diagnostic.FalsePositiveCount >= 2);
            Assert.True(diagnostic.HealthScore < 50, $"Expected false positives to drag the score below 50, got {diagnostic.HealthScore}.");
        }

        [Fact]
        public async Task Replay_Coverage_Improves_Health_Score()
        {
            RuleRuntimeTelemetryStore.Reset();
            var root = CreateTempDirectory();
            var journalOptions = new DetectionJournalOptions { DirectoryPath = Path.Combine(root, "journal") };
            await WriteEventAsync(journalOptions, CreateEvent("R102", 0.91));

            RuleRuntimeTelemetryStore.RecordSelectorSelected("R102", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordEvaluated("R102", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordMatched("R102", DateTime.UtcNow, 0.91);

            var noBenchmark = new RuleHealthDiagnosticsService(journalOptions, new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback-empty") }), benchmarkOutputDirectory: Path.Combine(root, "missing-benchmark"));
            var noCoverageScore = (await noBenchmark.SnapshotAsync()).Single(item => item.RuleId == "R102").HealthScore;

            var benchmarkRoot = Path.Combine(root, "benchmark");
            await SaveBenchmarkAsync(benchmarkRoot, new TuningBenchmarkReport
            {
                RuleCoverage =
                {
                    new TuningBenchmarkRuleCoverage
                    {
                        RuleId = "R102",
                        ReplayCoverageCount = 1,
                        BenignCoverageCount = 1,
                        BenignReplayFailures = 0,
                        MaliciousReplayFailures = 0,
                        AverageConfidence = 0.91
                    }
                }
            });

            var withBenchmark = new RuleHealthDiagnosticsService(journalOptions, new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback-covered") }), benchmarkOutputDirectory: benchmarkRoot);
            var withCoverageScore = (await withBenchmark.SnapshotAsync()).Single(item => item.RuleId == "R102").HealthScore;

            Assert.True(withCoverageScore > noCoverageScore, $"Expected replay coverage to improve health score, but {withCoverageScore} <= {noCoverageScore}.");
        }

        [Fact]
        public async Task Missing_Telemetry_Reduces_Health_Score()
        {
            RuleRuntimeTelemetryStore.Reset();
            var root = CreateTempDirectory();
            var journalOptions = new DetectionJournalOptions { DirectoryPath = Path.Combine(root, "journal") };
            await WriteEventAsync(journalOptions, CreateEvent("R084", 0.82));

            RuleRuntimeTelemetryStore.RecordSelectorSelected("R084", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordEvaluated("R084", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordMatched("R084", DateTime.UtcNow, 0.82);

            var baselineService = new RuleHealthDiagnosticsService(journalOptions, new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback-a") }), benchmarkOutputDirectory: Path.Combine(root, "benchmark-a"));
            var baselineScore = (await baselineService.SnapshotAsync()).Single(item => item.RuleId == "R084").HealthScore;

            RuleRuntimeTelemetryStore.RecordSelectorSkipped("R084", DateTime.UtcNow, missingTelemetry: true);
            RuleRuntimeTelemetryStore.RecordSelectorSkipped("R084", DateTime.UtcNow, missingTelemetry: true);
            RuleRuntimeTelemetryStore.RecordSelectorSkipped("R084", DateTime.UtcNow, missingTelemetry: true);

            var degradedService = new RuleHealthDiagnosticsService(journalOptions, new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback-b") }), benchmarkOutputDirectory: Path.Combine(root, "benchmark-b"));
            var degradedScore = (await degradedService.SnapshotAsync()).Single(item => item.RuleId == "R084").HealthScore;

            Assert.True(degradedScore < baselineScore, $"Expected missing telemetry to reduce health score, but {degradedScore} >= {baselineScore}.");
        }

        [Fact]
        public async Task Noisy_Rules_Get_Shadow_Recommendation()
        {
            RuleRuntimeTelemetryStore.Reset();
            var root = CreateTempDirectory();
            var journalOptions = new DetectionJournalOptions { DirectoryPath = Path.Combine(root, "journal") };
            var feedbackStore = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback") });

            await WriteEventAsync(journalOptions, CreateEvent("R148", 0.66, DetectionSuppressionStatus.Shadowed));
            await WriteEventAsync(journalOptions, CreateEvent("R148", 0.64, DetectionSuppressionStatus.Shadowed));
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R148", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.FalsePositive });
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R148", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.FalsePositive });
            RuleRuntimeTelemetryStore.RecordSelectorSelected("R148", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordEvaluated("R148", DateTime.UtcNow);

            await SaveBenchmarkAsync(Path.Combine(root, "benchmark"), new TuningBenchmarkReport
            {
                RuleCoverage =
                {
                    new TuningBenchmarkRuleCoverage
                    {
                        RuleId = "R148",
                        ReplayCoverageCount = 0,
                        BenignCoverageCount = 1,
                        BenignReplayFailures = 1,
                        MaliciousReplayFailures = 0
                    }
                }
            });

            var service = new RuleHealthDiagnosticsService(journalOptions, feedbackStore, benchmarkOutputDirectory: Path.Combine(root, "benchmark"));
            var diagnostic = (await service.SnapshotAsync()).Single(item => item.RuleId == "R148");

            Assert.Equal(RuleMode.Shadow, diagnostic.RecommendedMode);
        }

        [Fact]
        public async Task Stable_High_Confidence_Rules_Get_Alert_Recommendation()
        {
            RuleRuntimeTelemetryStore.Reset();
            var root = CreateTempDirectory();
            var journalOptions = new DetectionJournalOptions { DirectoryPath = Path.Combine(root, "journal") };
            var feedbackStore = new DetectionFeedbackStore(new DetectionFeedbackOptions { DirectoryPath = Path.Combine(root, "feedback") });
            await WriteEventAsync(journalOptions, CreateEvent("R102", 0.93));
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R102", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.TruePositive });
            await feedbackStore.AppendAsync(new DetectionFeedback { RuleId = "R102", EventId = Guid.NewGuid().ToString("N"), Verdict = DetectionFeedbackVerdict.TruePositive });
            RuleRuntimeTelemetryStore.RecordSelectorSelected("R102", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordEvaluated("R102", DateTime.UtcNow);
            RuleRuntimeTelemetryStore.RecordMatched("R102", DateTime.UtcNow, 0.93);

            await SaveBenchmarkAsync(Path.Combine(root, "benchmark"), new TuningBenchmarkReport
            {
                RuleCoverage =
                {
                    new TuningBenchmarkRuleCoverage
                    {
                        RuleId = "R102",
                        ReplayCoverageCount = 2,
                        BenignCoverageCount = 1,
                        BenignReplayFailures = 0,
                        MaliciousReplayFailures = 0,
                        AverageConfidence = 0.93
                    }
                }
            });

            var service = new RuleHealthDiagnosticsService(journalOptions, feedbackStore, benchmarkOutputDirectory: Path.Combine(root, "benchmark"));
            var diagnostic = (await service.SnapshotAsync()).Single(item => item.RuleId == "R102");

            Assert.Equal(RuleMode.Alert, diagnostic.RecommendedMode);
            Assert.True(diagnostic.HealthScore >= 60, $"Expected a healthy score for stable high-confidence content, got {diagnostic.HealthScore}.");
        }

        private static async Task WriteEventAsync(DetectionJournalOptions options, DetectionEvent evt)
        {
            var journal = new DetectionJournal(options);
            var result = await journal.AppendAsync(evt);
            Assert.True(result.Succeeded, result.ErrorMessage ?? "journal write failed");
        }

        private static DetectionEvent CreateEvent(string ruleId, double confidence, DetectionSuppressionStatus suppressionStatus = DetectionSuppressionStatus.None)
            => new()
            {
                EventId = Guid.NewGuid().ToString("N"),
                RuleId = ruleId,
                RuleName = ruleId,
                TimestampUtc = DateTime.UtcNow,
                PersistedAtUtc = DateTime.UtcNow,
                SourceIp = "10.0.0.5",
                DestinationIp = "198.51.100.5",
                DestinationPort = 443,
                Protocol = "HTTP",
                Summary = "test",
                Severity = SeverityLevel.High,
                ConfidenceScore = confidence,
                ConfidenceLabel = ConfidenceBuilder.Label(confidence),
                SuppressionStatus = suppressionStatus,
                DeliveryStatus = DetectionDeliveryStatus.Persisted
            };

        private static async Task SaveBenchmarkAsync(string outputDirectory, TuningBenchmarkReport report)
        {
            report.GeneratedAtUtc = DateTime.UtcNow;
            report.Name = "test-benchmark";
            report.ReplayDirectory = outputDirectory;
            await new TuningBenchmarkReportStore().SaveAsync(report, outputDirectory);
        }

        private static string CreateTempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), "carthago-health-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }
    }
}
