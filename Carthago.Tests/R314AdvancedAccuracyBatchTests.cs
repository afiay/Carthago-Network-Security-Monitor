// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R314AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch311315Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R314_SMTPAuthenticationFailureBurstRule().EvaluateAsync(NetworkBatch311315Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Smtp535_Info_Is_Not_Parsed_Server_Response() { var r=Sample();r.DestinationPort=587;r.Info="535 5.7.8 Authentication failed";Assert.False(await Hit(r)); }
    [Fact] public async Task Smtp465_Is_Encrypted_Without_Audit() { var r=Sample();r.DestinationPort=465;r.ApplicationProtocol="SMTPS";Assert.False(await Hit(r)); }
    [Fact] public async Task AuthLogin_String_Is_Not_Authentication_Outcome() { var r=Sample();r.Info="AUTH LOGIN";r.DestinationPort=25;Assert.False(await Hit(r)); }
    [Fact] public async Task Port587_Alone_Is_Not_Failed_Login() { var r=Sample();r.DestinationPort=587;Assert.False(await Hit(r)); }
    [Fact] public async Task Four_Packets_Are_Not_Four_Account_Failures() { var r=Sample();r.Info="four 535 failures";r.Length=500;Assert.False(await Hit(r)); }
    [Fact] public async Task HttpUri_535_String_Is_Not_Smtp_Reply() { var r=Sample();r.HttpUri="/535-auth-failed";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R314 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R314_SMTPAuthenticationFailureBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R314_SMTPAuthenticationFailureBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R314_SMTPAuthenticationFailureBurstRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R314_SMTPAuthenticationFailureBurstRule().PrecisionProfile;Assert.Equal(74,p.MinimumConfidence);Assert.Equal(4,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
