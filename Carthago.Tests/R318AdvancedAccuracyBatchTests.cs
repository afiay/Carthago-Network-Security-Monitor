// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R318AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch316320Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R318_EWSEnumerationBurstRule().EvaluateAsync(NetworkBatch316320Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task EwsExchangeAsmx_Path_Is_Not_Operation_Result() { var r=Sample();r.HttpUri="/ews/exchange.asmx";Assert.False(await Hit(r)); }
    [Fact] public async Task FindItem_Info_Is_Not_Parsed_Soap() { var r=Sample();r.Info="FindItem 200 OK";Assert.False(await Hit(r)); }
    [Fact] public async Task GetFolder_Info_Is_Not_Authorized_Mailbox_Audit() { var r=Sample();r.Info="GetFolder mailbox enumeration";Assert.False(await Hit(r)); }
    [Fact] public async Task Five_Requests_Do_Not_Prove_Enumeration() { var r=Sample();r.Info="five EWS requests";Assert.False(await Hit(r)); }
    [Fact] public async Task Tls443_Does_Not_Expose_Ews_Operation() { var r=Sample();r.DestinationPort=443;r.ApplicationProtocol="TLS";Assert.False(await Hit(r)); }
    [Fact] public async Task Migration_Process_Is_Not_Trusted_Audit() { var r=Sample();r.ProcessName="migration.exe";r.ProcessId=804;Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R318 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R318_EWSEnumerationBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R318_EWSEnumerationBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R318_EWSEnumerationBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R318_EWSEnumerationBurstRule().PrecisionProfile;Assert.Equal(74,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
