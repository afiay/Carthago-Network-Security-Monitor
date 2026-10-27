// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R162AdvancedAccuracyBatchTests
{

    [Fact] public async Task Redis_Port_With_Stats_Path_Matches()
    {
        var r=NetworkBatch156165Context.Http("/stats");r.DestinationPort=6379;
        Assert.True((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Memcached_Named_Host_With_Flush_Path_Matches()
    {
        var r=NetworkBatch156165Context.Http("/flush_all");r.HttpHost="memcached-internal.local";r.HttpRequestHeaders="Host: memcached-internal.local";
        Assert.True((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Generic_Web_Stats_Are_Benign()
    {
        Assert.False((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/stats")))).Matched);
    }
    [Fact] public async Task Stats_Lookalike_Does_Not_Qualify()
    {
        var r=NetworkBatch156165Context.Http("/statsdashboard");r.DestinationPort=6379;
        Assert.False((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Redis_Label_Is_Not_Service_Attribution()
    {
        var r=NetworkBatch156165Context.Http("/home");r.Info="redis flush_all";
        Assert.False((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_To_Internal_Admin_Request_Is_Out_Of_Scope()
    {
        var r=NetworkBatch156165Context.Http("/stats");r.DestinationPort=6379;r.Source="10.156.0.10";
        Assert.False((await new R162_RedisMemcachedWebProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Is_Not_New_Probe()
    {
        var rule=new R162_RedisMemcachedWebProbeRule();var r=NetworkBatch156165Context.Http("/stats");r.DestinationPort=6379;
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,2))).Matched);
    }
    [Fact] public void Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R162_RedisMemcachedWebProbeRule().PrecisionProfile;
        Assert.Equal(72,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
