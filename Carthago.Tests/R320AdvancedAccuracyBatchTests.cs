// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R320AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch316320Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R320_M365GraphMailExportPatternRule().EvaluateAsync(NetworkBatch316320Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task GraphHost_Is_Not_Export_Audit() { var r=Sample();r.HttpHost="graph.microsoft.com";Assert.False(await Hit(r)); }
    [Fact] public async Task MessagesPath_Is_Not_Export_Result() { var r=Sample();r.HttpUri="/v1.0/me/messages";Assert.False(await Hit(r)); }
    [Fact] public async Task UsersMessagesPath_Is_Not_Mailbox_Exfiltration() { var r=Sample();r.HttpUri="/v1.0/users/alice/messages";Assert.False(await Hit(r)); }
    [Fact] public async Task DeltaQuery_Is_Not_Export_Completion() { var r=Sample();r.HttpUri="/v1.0/me/mailFolders/inbox/messages/delta";Assert.False(await Hit(r)); }
    [Fact] public async Task ExportInfoClaim_Is_Untrusted() { var r=Sample();r.Info="Graph mail export successful";Assert.False(await Hit(r)); }
    [Fact] public async Task TlsSni_Is_Not_Authenticated_Graph_Audit() { var r=Sample();r.Sni="graph.microsoft.com";r.ApplicationProtocol="TLS";r.DestinationPort=443;Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R320 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R320_M365GraphMailExportPatternRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R320_M365GraphMailExportPatternRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R320_M365GraphMailExportPatternRule();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch316320Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R320_M365GraphMailExportPatternRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
