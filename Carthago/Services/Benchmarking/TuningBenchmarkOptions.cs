// SPDX-License-Identifier: MIT
// File: Services/Benchmarking/TuningBenchmarkOptions.cs
using System.Collections.Generic;
using System.IO;
using System.Linq;
using Carthago.Engine.Rules.Tuning;

namespace Carthago.Services.Benchmarking
{
    public sealed class TuningBenchmarkOptions
    {
        public string Name { get; set; } = "Carthago tuning benchmark";
        public string ReplayDirectory { get; set; } = Path.Combine("Tests", "RuleReplaySamples");
        public string OutputDirectory { get; set; } = "build-verify";
        public List<string> Profiles { get; set; } = RuleTuningCatalog.Profiles.Select(static profile => profile.Name).ToList();
    }
}
