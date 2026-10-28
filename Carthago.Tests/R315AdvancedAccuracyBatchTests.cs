// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R315AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch311315Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R315_IMAPLoginFailureSprayRule().EvaluateAsync(NetworkBatch311315Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Imaps993_Hides_Authentication_Outcome() { var r=Sample();r.DestinationPort=993;r.ApplicationProtocol="IMAPS";Assert.False(await Hit(r)); }
    [Fact] public async Task Imap143_Port_Is_Not_Failure() { var r=Sample();r.DestinationPort=143;r.ApplicationProtocol="IMAP";Assert.False(await Hit(r)); }
    [Fact] public async Task Login_Failed_Info_Is_Not_Server_Audit() { var r=Sample();r.Info="IMAP LOGIN failed";Assert.False(await Hit(r)); }
    [Fact] public async Task Many_Accounts_String_Is_Not_Distinct_Accounts() { var r=Sample();r.Info="many accounts failed authentication";Assert.False(await Hit(r)); }
    [Fact] public async Task Client_Login_Command_Is_Not_Server_Failure() { var r=Sample();r.Info="A001 LOGIN user password";Assert.False(await Hit(r)); }
    [Fact] public async Task Repeated_Record_Without_Account_Outcomes_Is_Insufficient() { var r=Sample();r.DestinationPort=143;r.Info="five failed IMAP logins";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R315 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R315_IMAPLoginFailureSprayRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R315_IMAPLoginFailureSprayRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R315_IMAPLoginFailureSprayRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R315_IMAPLoginFailureSprayRule().PrecisionProfile;Assert.Equal(74,p.MinimumConfidence);Assert.Equal(5,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
