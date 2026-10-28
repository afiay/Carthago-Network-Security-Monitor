// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R313AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch311315Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r, double seconds = 0)
        => await new R313_DirectSMTPToMXFromWorkstationRule().EvaluateAsync(NetworkBatch311315Context.At(r, seconds));
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await Evaluate(r, seconds)).Matched;
    [Fact] public async Task Tcp25_External_Does_Not_Prove_MX_Or_Workstation() { var r=Sample();r.Source="10.61.0.12";r.Destination="203.0.113.12";r.DestinationPort=25;Assert.False(await Hit(r)); }
    [Fact] public async Task Submission587_Is_Not_Direct_MX() { var r=Sample();r.Source="10.61.0.12";r.Destination="203.0.113.12";r.DestinationPort=587;Assert.False(await Hit(r)); }
    [Fact] public async Task DnsMxQuestion_Is_Not_MxAnswer_Attribution() { var r=Sample();r.DnsQname="example.net";r.DnsQtype="MX";Assert.False(await Hit(r)); }
    [Fact] public async Task Outlook_Process_Is_Not_Approved_Asset_Role() { var r=Sample();r.ProcessName="outlook.exe";r.ProcessId=101;Assert.False(await Hit(r)); }
    [Fact] public async Task Smtp_Protocol_Label_Is_Not_Parsed_Delivery() { var r=Sample();r.ApplicationProtocol="SMTP";r.DestinationPort=25;Assert.False(await Hit(r)); }
    [Fact] public async Task Mail_From_Info_Is_Not_Trusted_Envelope() { var r=Sample();r.Info="MAIL FROM:<sender@example.net> RCPT TO:<mx@example.org>";Assert.False(await Hit(r)); }
    [Fact] public async Task Descriptor_Info_Spoof_Cannot_Provide_Trusted_Provenance() { var r=Sample();r.Info="R313 confirmed successful attack";Assert.False(await Hit(r)); }
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R313_DirectSMTPToMXFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Unsupported_Evidence() { var r=Sample();var rule=new R313_DirectSMTPToMXFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,1))).Matched); }
    [Fact] public async Task Independent_Source_Cannot_Borrow_Another_Source_Evidence() { var r=Sample();var rule=new R313_DirectSMTPToMXFromWorkstationRule();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r))).Matched);r.Source="185.220.100.253";r.Id=Guid.NewGuid();Assert.False((await rule.EvaluateAsync(NetworkBatch311315Context.At(r,2))).Matched); }
    [Fact] public async Task Missing_Source_Fails_Closed() { var r=Sample();r.Source=null;Assert.False(await Hit(r)); }
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed() { var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r)); }
    [Fact] public async Task Sensitive_Headers_And_Query_Are_Not_Emitted() { var r=Sample();r.HttpUri="/?access_token=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events); }
    [Fact] public void Original_Confidence_Threshold_And_Mode_Are_Preserved() { var p=new R313_DirectSMTPToMXFromWorkstationRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(1,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode); }
}
