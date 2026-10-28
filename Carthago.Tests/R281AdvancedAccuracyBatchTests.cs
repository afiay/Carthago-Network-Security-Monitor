// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R281AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()=>NetworkBatch281285Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r,double seconds=0)
        =>await new R281_SuspiciousAdminConsoleLoginToCloudRule().EvaluateAsync(NetworkBatch281285Context.At(r,seconds));
    private static async Task<bool> Hit(TrafficRecord r,double seconds=0)=>(await Evaluate(r,seconds)).Matched;
    [Fact] public async Task Admin_Portal_Http_Is_Not_Trusted_Outcome(){var r=Sample();r.HttpHost="portal.azure.com";r.HttpUri="/";Assert.False(await Hit(r));}
    [Fact] public async Task Admin_Sni_Is_Not_Trusted_Outcome(){var r=Sample();r.Sni="admin.microsoft.com";r.HttpUri=null;Assert.False(await Hit(r));}
    [Fact] public async Task Admin_UserAgent_Is_Not_Trusted_Outcome(){var r=Sample();r.HttpUserAgent="global admin";Assert.False(await Hit(r));}
    [Fact] public async Task Login_Post_Is_Not_Trusted_Outcome(){var r=Sample();r.HttpMethod="POST";r.HttpUri="/admin/login";Assert.False(await Hit(r));}
    [Fact] public async Task GeoIp_Is_Not_Trusted_Outcome(){var r=Sample();r.SrcCountry="US";r.DstCountry="DE";Assert.False(await Hit(r));}
    [Fact] public async Task Info_Spoof_Is_Not_Trusted(){var r=Sample();r.Info="R281 verified compromise";Assert.False(await Hit(r));}
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Evidence(){var r=Sample();var rule=new R281_SuspiciousAdminConsoleLoginToCloudRule();Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,1))).Matched);}
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Evidence(){var r=Sample();var rule=new R281_SuspiciousAdminConsoleLoginToCloudRule();Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,1))).Matched);}
    [Fact] public async Task Missing_Source_Fails_Closed(){var r=Sample();r.Source=null;Assert.False(await Hit(r));}
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed(){var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r));}
    [Fact] public async Task Sensitive_Headers_Are_Not_Emitted(){var r=Sample();r.HttpUri="/callback?code=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events);}
    [Fact] public void Original_Profile_Is_Preserved(){var p=new R281_SuspiciousAdminConsoleLoginToCloudRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);}
}
