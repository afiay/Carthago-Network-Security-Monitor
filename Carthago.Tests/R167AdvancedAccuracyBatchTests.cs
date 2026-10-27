// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R167AdvancedAccuracyBatchTests
{
    [Fact] public async Task Concrete_Git_Config_Probe_Is_Observable()
    {
        Assert.True((await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.git/config")))).Matched);
    }
    [Fact] public async Task Github_Workflow_Directory_Is_Not_Git_Internal()
    {
        Assert.False((await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.github/workflows/build.yml")))).Matched);
    }
    [Fact] public async Task Gitignore_File_Is_Not_Repository_Metadata_Leak()
    {
        Assert.False((await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Http("/.gitignore")))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Attributed_Http()
    {
        var r=NetworkBatch166175Context.Http("/.git/config"); r.IsUdp=true;r.IsTcp=false; Assert.False((await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Authority_Is_Rejected()
    {
        var r=NetworkBatch166175Context.Http("/.git/config");r.HttpRequestHeaders="Host: different.example";Assert.False((await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Same_Packet_Cannot_Qualify_Twice()
    {
        var rule=new R167_GitDirectoryExposureProbeRule();var r=NetworkBatch166175Context.Http("/.git/config");Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Independent_Sources_Remain_Independent()
    {
        var rule=new R167_GitDirectoryExposureProbeRule();var a=NetworkBatch166175Context.Http("/.git/config");var b=NetworkBatch166175Context.Http("/.git/config");b.Source="203.0.113.167";b.Id=a.Id;Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(a))).Matched);Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(b,1))).Matched);
    }
    [Fact] public async Task Branch_Name_And_Query_Are_Redacted()
    {
        var r=NetworkBatch166175Context.Http("/.git/refs/heads/SECRET167?token=HIDDEN167");var x=await new R167_GitDirectoryExposureProbeRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET167",StringComparison.Ordinal)||i.Value.Contains("HIDDEN167",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R167_GitDirectoryExposureProbeRule().PrecisionProfile;
        Assert.Equal(80,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
