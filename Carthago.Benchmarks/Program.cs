using System;
using System.IO;
using System.Linq;
using Carthago.Services.Benchmarking;
using Carthago.Services;

var options = new TuningBenchmarkOptions();
var verbose = false;
var compareProfiles = false;
var explainShadow = false;
for (var i = 0; i < args.Length; i++)
{
    switch (args[i])
    {
        case "--replay-dir" when i + 1 < args.Length:
            options.ReplayDirectory = args[++i];
            break;
        case "--output-dir" when i + 1 < args.Length:
            options.OutputDirectory = args[++i];
            break;
        case "--name" when i + 1 < args.Length:
            options.Name = args[++i];
            break;
        case "--verbose":
            verbose = true;
            break;
        case "--compare-profiles":
            compareProfiles = true;
            break;
        case "--explain-shadow":
            explainShadow = true;
            break;
        default:
            Console.Error.WriteLine($"Unknown or incomplete argument: {args[i]}");
            Environment.ExitCode = 2;
            return;
    }
}

var runner = new TuningBenchmarkRunner();
var store = new TuningBenchmarkReportStore();
var repoRulesPath = Path.Combine("Carthago", "rules.json");
if (File.Exists(repoRulesPath))
    RuleEngine.LoadConfig(repoRulesPath);
else if (File.Exists("rules.json"))
    RuleEngine.LoadConfig("rules.json");

var report = await runner.RunAsync(options);
await store.SaveAsync(report, options.OutputDirectory);

Console.WriteLine($"Benchmark: {report.Name}");
Console.WriteLine($"Samples: {report.Summary.ReplaySampleCount}");
Console.WriteLine($"Supported malicious samples: {report.Summary.MaliciousSampleCount}");
Console.WriteLine($"Unsupported malicious samples: {report.Summary.UnsupportedMaliciousSampleCount} ({report.Summary.UnsupportedRuleCount} rule contracts)");
Console.WriteLine($"Supported-detector true-positive pass rate: {report.Summary.TruePositivePassRate:P1}");
Console.WriteLine($"Benign false positives: {report.Summary.BenignFalsePositiveCount}");
Console.WriteLine($"Noisy rules: {string.Join(", ", report.Summary.NoisyRules.Take(10))}");
Console.WriteLine($"Output: {store.GetJsonPath(options.OutputDirectory)}");
if (report.Summary.SampleLevelQuality is { } quality)
{
    var correct = quality.TruePositives + quality.TrueNegatives;
    var total = correct + quality.FalsePositives + quality.FalseNegatives;
    Console.WriteLine($"Sample-level accuracy ({Carthago.Engine.Rules.Tuning.RuleTuningCatalog.DefaultProfileName} / {TuningBenchmarkDeploymentStates.ColdUnconfigured}): {(total == 0 ? "N/A" : ((double)correct / total).ToString("P1"))}");
    Console.WriteLine($"Precision: {FormatMetric(quality.Precision)}  Recall: {FormatMetric(quality.Recall)}  F1: {FormatMetric(quality.F1Score)}");
    Console.WriteLine("Scope: supported malicious + benign labeled replays; UnsupportedMalicious producer gaps are reported separately.");
}
if (verbose)
{
    Console.WriteLine("\nExpected-rule diagnostics:");
    foreach (var sample in report.SampleResults)
    {
        Console.WriteLine($"[{sample.Classification}] {sample.Name}");
        foreach (var rule in sample.ExpectedRuleDiagnostics)
        {
            Console.WriteLine($"  {rule.RuleId}: {rule.Outcome}");
            if (rule.Outcome != "Matched")
            {
                if (rule.MissingRequiredTelemetry.Count > 0)
                    Console.WriteLine($"    Missing telemetry: {string.Join(", ", rule.MissingRequiredTelemetry)}");
                foreach (var reason in rule.NoMatchReasons)
                    Console.WriteLine($"    Reason: {reason}");
            }
        }
        foreach (var error in sample.Errors)
            Console.WriteLine($"  Assertion: {error}");
    }
}
if (compareProfiles)
{
    Console.WriteLine("\nDeployment-state alert quality (TP / FP / FN / TN):");
    foreach (var state in report.DeploymentStates.Values.OrderBy(static item => item.StateName, StringComparer.OrdinalIgnoreCase))
    {
        Console.WriteLine($"  [{state.StateName}] baselineReady={state.SimulatedBaselineReady} learning={state.SimulatedBaselineLearningMode} environment={state.EnvironmentConfigurationSource}");
        foreach (var pair in state.SampleLevelQualityByProfile.OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            var q = pair.Value;
            Console.WriteLine($"    {pair.Key,-15} {q.TruePositives,2} / {q.FalsePositives,2} / {q.FalseNegatives,2} / {q.TrueNegatives,2}  " +
                              $"precision={FormatMetric(q.Precision),6} recall={FormatMetric(q.Recall),6} F1={FormatMetric(q.F1Score),6}");
        }
    }

    if (report.DeploymentStates.TryGetValue(TuningBenchmarkDeploymentStates.ColdUnconfigured, out var cold)
        && report.DeploymentStates.TryGetValue(TuningBenchmarkDeploymentStates.CalibratedConfigured, out var calibrated))
    {
        Console.WriteLine("\nCalibration recall lift:");
        foreach (var profileName in cold.SampleLevelQualityByProfile.Keys
            .Intersect(calibrated.SampleLevelQualityByProfile.Keys, StringComparer.OrdinalIgnoreCase)
            .OrderBy(static name => name, StringComparer.OrdinalIgnoreCase))
        {
            var coldRecall = cold.SampleLevelQualityByProfile[profileName].Recall;
            var calibratedRecall = calibrated.SampleLevelQualityByProfile[profileName].Recall;
            var lift = coldRecall.HasValue && calibratedRecall.HasValue
                ? calibratedRecall.Value - coldRecall.Value
                : (double?)null;
            Console.WriteLine($"  {profileName,-15} cold={FormatMetric(coldRecall),6} calibrated={FormatMetric(calibratedRecall),6} lift={FormatMetric(lift),6} " +
                              $"FP {cold.SampleLevelQualityByProfile[profileName].FalsePositives}->{calibrated.SampleLevelQualityByProfile[profileName].FalsePositives}");
        }
    }

    Console.WriteLine("\nLabeled replay quality by alert profile — ColdUnconfigured compatibility view (TP / FP / FN / TN):");
    foreach (var pair in report.Summary.SampleLevelQualityByProfile.OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
    {
        var q = pair.Value;
        Console.WriteLine($"{pair.Key,-15} {q.TruePositives,2} / {q.FalsePositives,2} / {q.FalseNegatives,2} / {q.TrueNegatives,2}  " +
                          $"precision={FormatMetric(q.Precision),6} recall={FormatMetric(q.Recall),6} F1={FormatMetric(q.F1Score),6}");
    }
    Console.WriteLine("Scope: labeled replay samples only; raw matches and shadow decisions are not alerts.");
}
if (explainShadow)
{
    Console.WriteLine("\nUnsupported malicious scenarios (trusted producer unavailable; excluded from recall denominators):");
    foreach (var sample in report.SampleResults.Where(static item =>
        item.Classification == ReplaySampleClassification.UnsupportedMalicious))
    {
        foreach (var ruleId in sample.UnsupportedRuleIds)
        {
            var requiredCode = sample.UnsupportedReasonCodesByRuleId.TryGetValue(ruleId, out var code)
                ? code : "UNSPECIFIED";
            var diagnostic = sample.ExpectedRuleDiagnostics.FirstOrDefault(item =>
                string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
            Console.WriteLine($"  {sample.Name} / {ruleId}: required fail-closed reason={requiredCode}; outcome={diagnostic?.Outcome ?? "NoDiagnostic"}");
        }
    }

    Console.WriteLine("\nExpected supported malicious rules not alerting — ColdUnconfigured (profile policy diagnostics):");
    foreach (var sample in report.SampleResults.Where(static item => item.Classification == ReplaySampleClassification.Malicious))
    {
        foreach (var profile in sample.Profiles.OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
        {
            foreach (var ruleId in sample.ExpectedMatches.Where(id => !profile.Value.AlertRuleIds.Contains(id, StringComparer.OrdinalIgnoreCase)))
            {
                var trace = profile.Value.RuleDecisions.FirstOrDefault(item => string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
                if (trace == null)
                {
                    Console.WriteLine($"  {profile.Key} / {sample.Name} / {ruleId}: no rule match");
                    continue;
                }

                Console.WriteLine($"  {profile.Key} / {sample.Name} / {ruleId}: {trace.EffectiveMode} " +
                                  $"(tier={trace.Tier}, profile={trace.DefaultMode}, precision={trace.PrecisionMode}, " +
                                  $"confidence={trace.Confidence:F2}, floor={trace.ConfidenceFloor?.ToString("F2") ?? "none"})");
                Console.WriteLine($"    Reasons: {string.Join(", ", trace.Reasons)}");
                foreach (var reason in trace.RuntimePrecisionReasons)
                    Console.WriteLine($"    Precision: {reason}");
            }
        }
    }

    if (report.DeploymentStates.TryGetValue(TuningBenchmarkDeploymentStates.CalibratedConfigured, out _))
    {
        Console.WriteLine("\nRemaining supported malicious rules not alerting — CalibratedConfigured:");
        foreach (var sample in report.SampleResults.Where(static item => item.Classification == ReplaySampleClassification.Malicious))
        {
            var profiles = TuningBenchmarkDeploymentStates.ProfilesFor(
                sample, TuningBenchmarkDeploymentStates.CalibratedConfigured);
            foreach (var profile in profiles.OrderBy(static pair => pair.Key, StringComparer.OrdinalIgnoreCase))
            {
                foreach (var ruleId in sample.ExpectedMatches.Where(id =>
                    !profile.Value.AlertRuleIds.Contains(id, StringComparer.OrdinalIgnoreCase)))
                {
                    var trace = profile.Value.RuleDecisions.FirstOrDefault(item =>
                        string.Equals(item.RuleId, ruleId, StringComparison.OrdinalIgnoreCase));
                    if (trace == null)
                    {
                        Console.WriteLine($"  {profile.Key} / {sample.Name} / {ruleId}: no policy decision");
                        continue;
                    }

                    Console.WriteLine($"  {profile.Key} / {sample.Name} / {ruleId}: {trace.EffectiveMode} " +
                                      $"(tier={trace.Tier}, profile={trace.DefaultMode}, precision={trace.PrecisionMode}, " +
                                      $"confidence={trace.Confidence:F2}, floor={trace.ConfidenceFloor?.ToString("F2") ?? "none"})");
                    foreach (var reason in trace.RuntimePrecisionReasons)
                        Console.WriteLine($"    Precision: {reason}");
                }
            }
        }
    }
}

static string FormatMetric(double? value) => value.HasValue ? value.Value.ToString("P1") : "N/A";
