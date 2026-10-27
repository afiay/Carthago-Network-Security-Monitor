// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R161AdvancedAccuracyBatchTests
{

    [Fact] public async Task Docker_Containers_Listing_On_Daemon_Port_Matches()
    {
        var r=NetworkBatch156165Context.Http("/containers/json");r.DestinationPort=2375;
        Assert.True((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Docker_Named_Host_With_Version_Path_Matches()
    {
        var r=NetworkBatch156165Context.Http("/version");r.HttpHost="docker-internal.local";r.HttpRequestHeaders="Host: docker-internal.local";
        Assert.True((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Generic_Version_Page_Is_Not_Docker()
    {
        Assert.False((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/version")))).Matched);
    }
    [Fact] public async Task Lookalike_Container_Path_Does_Not_Match()
    {
        var r=NetworkBatch156165Context.Http("/containers/jsonbackup");r.DestinationPort=2375;
        Assert.False((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Text_Is_Not_An_Observed_Docker_Request()
    {
        var r=NetworkBatch156165Context.Http("/home");r.DestinationPort=2375;r.Info="GET /containers/json";
        Assert.False((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Host_Header_Disagreement_Is_Rejected()
    {
        var r=NetworkBatch156165Context.Http("/containers/json");r.DestinationPort=2375;r.HttpRequestHeaders="Host: unrelated.test";
        Assert.False((await new R161_DockerApiTcpExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Id_Cannot_Match_Again()
    {
        var rule=new R161_DockerApiTcpExposureProbeRule();var r=NetworkBatch156165Context.Http("/containers/json");r.DestinationPort=2375;
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,5))).Matched);
    }
    [Fact] public void Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R161_DockerApiTcpExposureProbeRule().PrecisionProfile;
        Assert.Equal(78,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
