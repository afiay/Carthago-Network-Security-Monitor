using System;
using System.IO;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests
{
    public sealed class TuningBenchmarkTests
    {
        [Fact]
        public async Task Benchmark_Runs_Without_External_Services_And_Writes_Report()
        {
            var tempOutput = CreateTempDirectory();
            var runner = new TuningBenchmarkRunner();
            var store = new TuningBenchmarkReportStore();

            var report = await runner.RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory(),
                OutputDirectory = tempOutput
            });

            await store.SaveAsync(report, tempOutput);

            Assert.NotNull(report);
            Assert.True(report.SampleResults.Count >= 16);
            var quality = Assert.IsType<DetectionQualityMetrics>(report.Summary.SampleLevelQuality);
            Assert.Equal(report.SampleResults.Count, quality.TruePositives + quality.FalsePositives + quality.FalseNegatives + quality.TrueNegatives);
            Assert.True(File.Exists(store.GetJsonPath(tempOutput)));
            Assert.True(File.Exists(store.GetMarkdownPath(tempOutput)));
            var markdown = await File.ReadAllTextAsync(store.GetMarkdownPath(tempOutput));
            Assert.Contains("Precision:", markdown);
            Assert.Contains("Recall:", markdown);
            Assert.Contains("F1:", markdown);
        }

        [Fact]
        public async Task Benign_Samples_Do_Not_Generate_Critical_Alert_Spam()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            Assert.True(report.Summary.BenignCriticalAlertCount <= 1, $"Expected benign critical alert spam to stay near zero, but saw {report.Summary.BenignCriticalAlertCount}.");
            Assert.True(report.ProfileResults["HomeLab"].BenignCriticalAlertCount <= report.ProfileResults["Research"].BenignCriticalAlertCount);
        }

        [Fact]
        public async Task Malicious_Samples_Trigger_Expected_HighConfidence_Rules_And_Profiles_Differ()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var dnsTunnel = report.SampleResults.Single(sample => sample.Name == "dns-tunnel-high-confidence");
            var oauth = report.SampleResults.Single(sample => sample.Name == "oauth-device-code-phishing");
            var modbus = report.SampleResults.Single(sample => sample.Name == "modbus-write-function");

            Assert.Contains("R102", dnsTunnel.ActualMatches);
            Assert.True(dnsTunnel.MaximumConfidence >= 0.75, $"Expected high confidence for dns-tunnel-high-confidence, got {dnsTunnel.MaximumConfidence:F2}.");
            Assert.Contains("R275", oauth.ActualMatches);
            Assert.True(report.ProfileResults["Enterprise"].AlertCount >= report.ProfileResults["HomeLab"].AlertCount);
            Assert.Contains("R240", modbus.Profiles["OTSegment"].AlertRuleIds);
            Assert.DoesNotContain("R240", modbus.Profiles["HomeLab"].AlertRuleIds);
        }

        [Fact]
        public async Task Benchmark_Report_Lists_Tuning_Gaps()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            Assert.NotEmpty(report.Summary.RulesWithoutReplayCoverage);
            Assert.NotEmpty(report.Summary.RulesWithoutBenignCoverage);
            Assert.NotEmpty(report.Summary.ConfidenceDistribution);
        }

        [Fact]
        public async Task Benchmark_Compares_Alert_Quality_For_Every_Profile()
        {
            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions
            {
                ReplayDirectory = GetReplayDirectory()
            });

            Assert.Equal(report.ProfileResults.Keys.OrderBy(name => name),
                report.Summary.SampleLevelQualityByProfile.Keys.OrderBy(name => name));
            foreach (var quality in report.Summary.SampleLevelQualityByProfile.Values)
            {
                Assert.Equal(report.SampleResults.Count,
                    quality.TruePositives + quality.FalsePositives + quality.FalseNegatives + quality.TrueNegatives);
            }
            Assert.Equal(report.Summary.SampleLevelQuality,
                report.Summary.SampleLevelQualityByProfile["SmallBusiness"]);
        }

        [Fact]
        public async Task Benchmark_Explains_Why_Expected_Rules_Did_Not_Match()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var powerShell = report.SampleResults.Single(sample => sample.Name == "ad-psremoting-encoded-command");
            var diagnostic = Assert.Single(powerShell.ExpectedRuleDiagnostics);
            Assert.Equal("R343", diagnostic.RuleId);
            Assert.Equal("Matched", diagnostic.Outcome);
            Assert.Empty(diagnostic.MissingRequiredTelemetry);

            var oauth = report.SampleResults.Single(sample => sample.Name == "oauth-device-code-phishing");
            Assert.Contains(oauth.ExpectedRuleDiagnostics, item => item.RuleId == "R275" && item.Outcome == "Matched");
        }

        [Fact]
        public async Task Incomplete_PowerShell_Replay_Reports_Missing_Telemetry()
        {
            var folder = CreateTempDirectory();
            var json = """
                {"name":"missing-process","records":[{"source":"10.0.0.70","destination":"10.0.0.20","protocol":"TCP","destinationPort":5985,"info":"WinRM Invoke-Command -EncodedCommand SQBFAFgA"}],"expectedMatches":["R343"]}
                """;
            await File.WriteAllTextAsync(Path.Combine(folder, "missing-process.json"), json);

            var report = await new TuningBenchmarkRunner().RunAsync(new TuningBenchmarkOptions { ReplayDirectory = folder });
            var sample = Assert.Single(report.SampleResults);
            var diagnostic = Assert.Single(sample.ExpectedRuleDiagnostics);
            Assert.Equal("R343", diagnostic.RuleId);
            Assert.Equal("MissingTelemetry", diagnostic.Outcome);
            Assert.Contains("precision.Process", diagnostic.MissingRequiredTelemetry);
        }

        [Fact]
        public async Task Evidence_Rich_Replays_Match_Their_Specific_Rules()
        {
            var runner = new TuningBenchmarkRunner();
            var report = await runner.RunAsync(new TuningBenchmarkOptions { ReplayDirectory = GetReplayDirectory() });

            var names = new[]
            {
                "ad-psremoting-encoded-command", "bacnet-write-property", "cloudflared-tunnel",
                "kubernetes-pod-exec", "rclone-exfil", "redis-config-set", "ssrf-imds"
            };
            foreach (var name in names)
            {
                var sample = report.SampleResults.Single(item => item.Name == name);
                Assert.True(sample.ExpectedMatches.All(rule => sample.ActualMatches.Contains(rule)),
                    $"{name}: missing {string.Join(", ", sample.MissingExpectedMatches)}; " +
                    string.Join("; ", sample.ExpectedRuleDiagnostics.Select(item =>
                        $"{item.RuleId}={item.Outcome} ({string.Join(", ", item.MissingRequiredTelemetry)}; {string.Join(", ", item.NoMatchReasons)})")));
            }
        }

        private static string GetReplayDirectory()
            => Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..", "Tests", "RuleReplaySamples");

        private static string CreateTempDirectory()
        {
            var path = Path.Combine(Path.GetTempPath(), "carthago-benchmark-" + Guid.NewGuid().ToString("N"));
            Directory.CreateDirectory(path);
            return path;
        }
    }
}
