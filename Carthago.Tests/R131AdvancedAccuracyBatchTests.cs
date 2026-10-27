// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R131AdvancedAccuracyBatchTests
{
    private readonly R131_HttpAuthenticationFailureSpikeRule _rule = new();

    [Fact] public async Task Fifteen_Independent_Auth_Failures_Reach_Threshold()
    {
        for (var i = 0; i < 14; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Failed(), i * 6))).Matched);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Failed(), 84))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "count" && x.Value == "15");
    }

    [Fact] public async Task Duplicate_Packet_Id_Cannot_Manufacture_Burst()
    {
        var packet = NetworkBatch131135Context.Failed();
        for (var i = 0; i < 17; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(packet, i))).Matched);
    }

    [Fact] public async Task Generic_Forbidden_And_Unauthenticated_Requests_Are_Negative()
    {
        for (var i = 0; i < 16; i++)
        {
            var r = NetworkBatch131135Context.Web("/static/app.js");
            r.Info = "403 forbidden";
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r, i))).Matched);
        }
    }

    [Fact] public async Task Status_Query_Alone_Is_Not_Authentication_Failure()
    {
        var r = NetworkBatch131135Context.Web("/api/auth/token?status=401");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Contradictory_Transport_And_Missing_Tcp_Are_Rejected()
    {
        var udp = NetworkBatch131135Context.Failed(); udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(udp))).Matched);
        var missing = NetworkBatch131135Context.Failed(); missing.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(missing))).Matched);
    }

    [Fact] public async Task Window_Expiry_Does_Not_Carry_Stale_Events()
    {
        for (var i = 0; i < 14; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Failed(), i))).Matched);
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Failed(), 360))).Matched);
    }

    [Fact] public async Task Host_Isolation_Prevents_Cross_Service_Burst()
    {
        for (var i = 0; i < 14; i++)
            Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Failed(), i))).Matched);
        var other = NetworkBatch131135Context.Failed(); other.HttpHost = "other.example.test"; other.Sni = other.HttpHost;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(other, 15))).Matched);
    }

    [Fact] public async Task Secret_Path_Is_Redacted_And_Shadow_Is_Unchanged()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, _rule.PrecisionProfile.MinimumConfidence);
        for (var i = 0; i < 14; i++)
        {
            var r = NetworkBatch131135Context.Failed(); r.HttpUri = "/api/auth/private-secret-131";
            await _rule.EvaluateAsync(NetworkBatch131135Context.At(r, i));
        }
        var last = NetworkBatch131135Context.Failed(); last.HttpUri = "/api/auth/private-secret-131";
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(last, 14))).Events);
        Assert.DoesNotContain("private-secret-131", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-131", StringComparison.Ordinal));
    }
}
