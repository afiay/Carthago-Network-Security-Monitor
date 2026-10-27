// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IPv6;
using Xunit;

namespace Carthago.Tests;

public sealed class R070AdvancedAccuracyBatchTests
{
    private readonly R070_Teredo6to4ISATAPTunnelUseRule _rule = new();
    private async Task<bool> Teredo(int s, string? app = "Teredo", int? port = 3544,
        string source = "8.8.8.8", string destination = "9.9.9.9")
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(s,source,destination,
            version:4,protocol:"UDP",icmp:null,ttl:null,application:app,destinationPort:port))).Matched;
    private async Task<bool> Ipv6(int s,string source,string? app)
        => (await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(s,source,"2001:db8::5",
            version:6,protocol:"TCP",icmp:null,ttl:null,application:app))).Matched;
    [Fact] public async Task Teredo_Requires_Two_Corroborated_Flow_Observations()
    { Assert.False(await Teredo(1)); Assert.True(await Teredo(2)); Assert.False(await Teredo(3)); }
    [Fact] public async Task Port_3544_Alone_Is_Not_Tunnel_Proof()
    { Assert.False(await Teredo(1,app:null)); Assert.False(await Teredo(2,app:"DNS")); }
    [Fact] public async Task App_Label_Without_Expected_Port_Is_Not_Tunnel_Proof()
    { Assert.False(await Teredo(1,port:53)); Assert.False(await Teredo(2,port:53)); }
    [Fact] public async Task Structured_SixToFour_Requires_Address_And_Protocol()
    { Assert.False(await Ipv6(1,"2002:c000:201::1","6to4")); Assert.True(await Ipv6(2,"2002:c000:201::1","6to4")); }
    [Fact] public async Task Structured_Isatap_Requires_Interface_Identifier()
    { Assert.False(await Ipv6(1,"2001:db8:1:2:0:5efe:c000:201","ISATAP")); Assert.True(await Ipv6(2,"2001:db8:1:2:0:5efe:c000:201","ISATAP")); }
    [Fact] public async Task Text_Only_And_Normal_Ipv6_Do_Not_Alert()
    { Assert.False(await Ipv6(1,"2001:db8::1","6to4")); Assert.False(await Ipv6(2,"2001:db8::1","ISATAP")); }
    [Fact] public async Task Duplicate_And_Out_Of_Order_Observations_Do_Not_Confirm()
    { Assert.False(await Teredo(2)); Assert.False(await Teredo(2)); Assert.False(await Teredo(1)); Assert.True(await Teredo(3)); }
    [Fact] public async Task Ten_Minute_Inactivity_Rearms_Flow_Without_Immediate_Alert()
    { Assert.False(await Teredo(1)); Assert.True(await Teredo(2)); Assert.False(await Teredo(700)); Assert.True(await Teredo(701)); }
    [Fact] public async Task Independent_Flows_Do_Not_Combine_Observations()
    { Assert.False(await Teredo(1)); Assert.False(await Teredo(2,destination:"1.1.1.1")); Assert.True(await Teredo(3)); }
    [Fact] public async Task Alert_Redacts_Application_Text_And_Mac()
    { Assert.False(await Teredo(1)); var r=await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(2,"8.8.8.8","9.9.9.9",version:4,protocol:"UDP",icmp:null,ttl:null,mac:"00:11:22:33:44:55",application:"Teredo",destinationPort:3544,info:"private-payload")); var e=Assert.Single(r.Events); Assert.DoesNotContain("private-payload",e.Evidence); Assert.DoesNotContain("00:11:22",e.Description); }
    [Fact] public async Task Cancellation_Prevents_Sequence_State_Advance()
    { using var cancel=new CancellationTokenSource(); cancel.Cancel(); await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(Ipv6Batch066070Context.Packet(1,version:4,protocol:"UDP",icmp:null,ttl:null,application:"Teredo",destinationPort:3544,source:"8.8.8.8",destination:"9.9.9.9"),cancel.Token)); }
}
