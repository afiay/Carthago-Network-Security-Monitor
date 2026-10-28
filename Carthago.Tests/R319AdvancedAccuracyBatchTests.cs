// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R319AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch316320Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R319_OWAAdminOrECPProbeRule().EvaluateAsync(NetworkBatch316320Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Ecp_Path_Is_Not_Verified_Exchange_Admin() { var r=Sample();r.HttpUri="/ecp/default.aspx";Assert.False(await Hit(r)); }
    [Fact] public async Task Owa_Path_Is_Not_Administrative_Probe() { var r=Sample();r.HttpUri="/owa";Assert.False(await Hit(r)); }
    [Fact] public async Task External_Source_Is_Not_Unauthorized_Actor() { var r=Sample();r.Source="185.220.100.253";r.HttpUri="/ecp";Assert.False(await Hit(r)); }
    [Fact] public async Task Exchange_Control_Panel_Info_Is_Untrusted() { var r=Sample();r.Info="Exchange Control Panel admin probe";Assert.False(await Hit(r)); }
    [Fact] public async Task Port443_Does_Not_Identify_Admin_Listener() { var r=Sample();r.DestinationPort=443;r.ApplicationProtocol="TLS";Assert.False(await Hit(r)); }
    [Fact] public async Task Browser_Process_Name_Is_Not_Authentication_Audit() { var r=Sample();r.ProcessName="chrome.exe";r.ProcessId=988;Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R319 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R319_OWAAdminOrECPProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R319_OWAAdminOrECPProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R319_OWAAdminOrECPProbeRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R319_OWAAdminOrECPProbeRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
