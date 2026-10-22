using System;
using System.IO;
using System.Linq;
using Carthago.Services.Benchmarking;
using Carthago.Services;

var options = new TuningBenchmarkOptions();
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
Console.WriteLine($"True-positive pass rate: {report.Summary.TruePositivePassRate:P1}");
Console.WriteLine($"Benign false positives: {report.Summary.BenignFalsePositiveCount}");
Console.WriteLine($"Noisy rules: {string.Join(", ", report.Summary.NoisyRules.Take(10))}");
Console.WriteLine($"Output: {store.GetJsonPath(options.OutputDirectory)}");
