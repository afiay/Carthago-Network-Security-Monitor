// SPDX-License-Identifier: MIT
using System;
using Carthago.Services;
using Carthago.Services.Baseline;
using Xunit;

namespace Carthago.Tests;

public sealed class Ga09LiveBaselineGateTests
{
    [Theory]
    [InlineData("R102")]
    [InlineData("R103")]
    public void Global_Readiness_Cannot_Qualify_Live_Dns(string ruleId)
    {
        var global = new BaselineReadiness(true, 1000, 100,
            TimeSpan.FromDays(2), Array.Empty<string>());
        var readiness = RuleEngine.ResolveLiveBaselineReadiness(ruleId, global);
        Assert.False(readiness.IsReady);
        Assert.Contains("qualified source/interface DNS baseline unavailable", readiness.Blockers);
    }

    [Fact]
    public void Other_Rules_Retain_Existing_Readiness()
    {
        var global = new BaselineReadiness(true, 1000, 100,
            TimeSpan.FromDays(2), Array.Empty<string>());
        Assert.Same(global, RuleEngine.ResolveLiveBaselineReadiness("R104", global));
    }
}
