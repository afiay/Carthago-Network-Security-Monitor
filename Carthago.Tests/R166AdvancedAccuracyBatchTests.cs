// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R166AdvancedAccuracyBatchTests
{
    [Fact] public async Task Concrete_Env_Secret_Path_Is_Observable()
    {
        Assert.True((await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.env")))).Matched);
    }
    [Fact] public async Task Example_Env_Template_Is_Benign()
    {
        Assert.False((await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.env.example")))).Matched);
    }
    [Fact] public async Task Env_Keyword_In_Documentation_Is_Not_Secret_File()
    {
        Assert.False((await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/docs/.env-guide")))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Cannot_Claim_Http_Secret_Probe()
    {
        var r=NetworkBatch166175Context.Http("/.env"); r.IsTcp=false; r.IsUdp=true; Assert.False((await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Conflicting_Host_Header_Is_Not_Trusted()
    {
        var r=NetworkBatch166175Context.Http("/.env"); r.HttpRequestHeaders="Host: attacker.example"; Assert.False((await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Raise_Second_Probe()
    {
        var rule=new R166_EnvironmentFileSecretProbeRule(); var r=NetworkBatch166175Context.Http("/.env"); Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched); Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Older_Observation_Cannot_Rewind_Replay_Guard()
    {
        var rule=new R166_EnvironmentFileSecretProbeRule(); Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.env"),10))).Matched); Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.env"),9))).Matched);
    }
    [Fact] public async Task Query_Secret_Never_Enters_New_Evidence()
    {
        var r=NetworkBatch166175Context.Http("/.env?access_token=SECRET166"); var x=await new R166_EnvironmentFileSecretProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r)); Assert.True(x.Matched); Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET166",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R166_EnvironmentFileSecretProbeRule().PrecisionProfile;
        Assert.Equal(78,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
