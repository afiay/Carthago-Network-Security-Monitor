// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R132AdvancedAccuracyBatchTests
{
    private readonly R132_RapidCountryChangeForSourceIdentityRule _rule = new();

    [Fact] public async Task Three_Attributed_Countries_For_One_Login_Identity_Match()
    {
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "US"), 0))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "DE"), 30))).Matched);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "SE"), 60))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "3");
    }

    [Fact] public async Task Repeated_Single_Country_Is_Not_Travel()
    {
        for (var i = 0; i < 6; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(), i))).Matched);
    }

    [Fact] public async Task Replayed_Id_With_Different_Geo_Cannot_Inflate_Count()
    {
        var r = NetworkBatch131135Context.Login(country: "US");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r, 0))).Matched);
        r.SrcCountryIso2 = "DE";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r, 20))).Matched);
        r.SrcCountryIso2 = "SE";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r, 40))).Matched);
    }

    [Fact] public async Task Missing_Or_NonCountry_Geo_Fails_Closed()
    {
        foreach (var code in new[] { "", "ZZ", "EU", "USA", "1A" })
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: code)))).Matched);
    }

    [Fact] public async Task Identity_And_Target_Isolation_Are_Preserved()
    {
        foreach (var code in new[] { "US", "DE" })
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login("alice@example.com", code)))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login("bob@example.com", "SE")))).Matched);
        var other = NetworkBatch131135Context.Login("alice@example.com", "SE");
        other.HttpHost = "other.example.test"; other.Sni = other.HttpHost;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(other))).Matched);
    }

    [Fact] public async Task Expired_Geo_Observations_Are_Not_Reused()
    {
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "US"), 0))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "DE"), 30))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "SE"), 700))).Matched);
    }

    [Fact] public async Task NonHttp_And_Missing_Identity_Are_Rejected()
    {
        var missing = NetworkBatch131135Context.Login("", "US"); missing.Info = "login successful";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(missing))).Matched);
        var udp = NetworkBatch131135Context.Login(); udp.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(udp))).Matched);
    }

    [Fact] public async Task Identity_Is_Pseudonymized_And_Shadow_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, _rule.PrecisionProfile.MinimumConfidence);
        await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "US"), 0));
        await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "DE"), 20));
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Login(country: "SE"), 40))).Events);
        Assert.DoesNotContain("alice@example.com", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("alice@example.com", StringComparison.OrdinalIgnoreCase));
        Assert.Contains(evt.StructuredEvidence.Items, x => x.Key == "identity.subject" && x.Value.StartsWith("sha256:", StringComparison.Ordinal));
    }
}
