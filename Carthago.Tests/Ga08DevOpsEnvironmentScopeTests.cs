// SPDX-License-Identifier: MIT
using System;
using System.IO;
using System.Linq;
using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Carthago.Services.Benchmarking;
using Xunit;

namespace Carthago.Tests;

// Temporary synthetic policy controls, independent of the scored development corpus.
[Collection("Legacy rules R011-R015 isolated")]
public sealed class Ga08DevOpsEnvironmentScopeTests
{
    [Fact]
    public async Task Exact_CiCd_Scope_Qualifies_Strong_Matches_Without_Bypassing_Profile()
    {
        var source = Path.Combine(AppContext.BaseDirectory, "..", "..", "..", "..",
            "Tests", "RuleReplaySamples", "malicious");
        var directory = Path.Combine(Path.GetTempPath(), "carthago-ga08-" + Guid.NewGuid().ToString("N"));
        Directory.CreateDirectory(directory);
        try
        {
            var cases = new[]
            {
                (Id: "R353", Name: "ga07-r353-github-token-shaped-cleartext-request", Host: "api.github.com"),
                (Id: "R354", Name: "ga07-r354-gitlab-token-shaped-cleartext-request", Host: "gitlab.com"),
                (Id: "R359", Name: "ga07-r359-azure-pat-shaped-cleartext-query", Host: "dev.azure.com")
            };
            foreach (var item in cases)
            {
                foreach (var scope in new[] { "exact", "unrelated", "unrelated-attributed", "exact-attributed" })
                {
                    var fixture = JsonNode.Parse(await File.ReadAllTextAsync(
                        Path.Combine(source, item.Name + ".json")))!.AsObject();
                    var name = item.Name + "-" + scope;
                    fixture["name"] = name;
                    fixture["environmentTuning"] = new JsonObject
                    {
                        ["approved"] = new JsonObject
                        {
                            ["ciCdServers"] = new JsonArray(JsonValue.Create(
                                scope.StartsWith("exact", StringComparison.Ordinal) ? item.Host : "unrelated.example.invalid"))
                        }
                    };
                    if (scope.EndsWith("-attributed", StringComparison.Ordinal))
                    {
                        var record = fixture["records"]!.AsArray()[0]!.AsObject();
                        record["processName"] = "synthetic-client.exe";
                        record["macSource"] = "02:00:00:00:00:01";
                    }
                    await File.WriteAllTextAsync(Path.Combine(directory, name + ".json"),
                        fixture.ToJsonString());
                }
            }

            var report = await new TuningBenchmarkRunner().RunAsync(
                new TuningBenchmarkOptions { ReplayDirectory = directory });
            Assert.Equal(12, report.SampleResults.Count);
            foreach (var item in cases)
            {
                foreach (var scope in new[] { "exact", "unrelated", "unrelated-attributed", "exact-attributed" })
                {
                    var sample = Assert.Single(report.SampleResults,
                        value => value.Name == item.Name + "-" + scope);
                    Assert.Empty(sample.Errors);
                    Assert.Contains(item.Id, sample.ActualMatches);
                    var cold = sample.DeploymentStateProfiles["ColdUnconfigured"]["Enterprise"];
                    var calibrated = sample.DeploymentStateProfiles["CalibratedConfigured"]["Enterprise"];
                    Assert.DoesNotContain(item.Id, cold.AlertRuleIds);
                    Assert.Contains(item.Id, cold.ShadowRuleIds);
                    var trace = Assert.Single(calibrated.RuleDecisions, value => value.RuleId == item.Id);
                    Assert.True(trace.Confidence >= 0.78);
                    if (scope.StartsWith("exact", StringComparison.Ordinal))
                    {
                        Assert.Contains(item.Id, calibrated.AlertRuleIds);
                        Assert.Equal("Alert", trace.EffectiveMode);
                    }
                    else
                    {
                        Assert.DoesNotContain(item.Id, calibrated.AlertRuleIds);
                        Assert.Equal("Shadow", trace.EffectiveMode);
                        Assert.Contains(trace.RuntimePrecisionReasons, reason =>
                            reason.Contains("environment-scoped rule lacks", StringComparison.Ordinal));
                    }
                    // Profile Disabled must remain restrictive even when scope is present.
                    var home = sample.DeploymentStateProfiles["CalibratedConfigured"]["HomeLab"];
                    Assert.DoesNotContain(item.Id, home.AlertRuleIds);
                    Assert.Contains(item.Id, home.SuppressedRuleIds);
                }
            }
        }
        finally
        {
            Directory.Delete(directory, recursive: true);
        }
    }
}
