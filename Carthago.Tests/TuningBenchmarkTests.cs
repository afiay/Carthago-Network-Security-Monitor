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
            Assert.True(File.Exists(store.GetJsonPath(tempOutput)));
            Assert.True(File.Exists(store.GetMarkdownPath(tempOutput)));
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
