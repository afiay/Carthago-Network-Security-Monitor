// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R165AdvancedAccuracyBatchTests
{

    [Fact] public async Task External_Phpinfo_Php_Probe_Matches()
    {
        Assert.True((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/phpinfo.php")))).Matched);
    }
    [Fact] public async Task Exact_Phpinfo_Path_Matches()
    {
        Assert.True((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/phpinfo")))).Matched);
    }
    [Fact] public async Task Generic_Info_Page_Is_Benign()
    {
        Assert.False((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/info")))).Matched);
    }
    [Fact] public async Task Query_Flag_On_Unrelated_Page_Is_Not_Phpinfo()
    {
        Assert.False((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/home?phpinfo=1")))).Matched);
    }
    [Fact] public async Task Post_Method_Does_Not_Qualify_As_Read_Probe()
    {
        Assert.False((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/phpinfo.php","POST")))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Http()
    {
        var r=NetworkBatch156165Context.Http("/phpinfo.php");r.IsTcp=false;r.IsUdp=true;
        Assert.False((await new R165_PhpinfoExposureProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Id_Does_Not_Match_Twice()
    {
        var rule=new R165_PhpinfoExposureProbeRule();var r=NetworkBatch156165Context.Http("/phpinfo.php");
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,2))).Matched);
    }
    [Fact] public void Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R165_PhpinfoExposureProbeRule().PrecisionProfile;
        Assert.Equal(70,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
