// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using System.Threading.Tasks;
using Carthago.Engine.Rules.LateralMovement;
using Xunit;
namespace Carthago.Tests;
public sealed class R075AdvancedAccuracyBatchTests
{
    private readonly R075_WMIDCOMLateralMovementRule _rule=new();
    private async Task<bool> Seen(int s,string dst="10.71.1.1",string src="10.71.0.10",int port=135,string? app="WMI",ushort? flags=2,string protocol="TCP")
        => (await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(s,src,dst,port,flags,protocol,app))).Matched;
    [Fact] public async Task Three_Distinct_Classified_Wmi_Rpc_Targets_Trigger()
    {Assert.False(await Seen(1,dst:"10.71.1.1"));Assert.False(await Seen(2,dst:"10.71.1.2"));Assert.True(await Seen(3,dst:"10.71.1.3"));}
    [Fact] public async Task Three_Distinct_Classified_Dcom_Rpc_Targets_Trigger()
    {Assert.False(await Seen(1,dst:"10.71.1.1",app:"DCOM"));Assert.False(await Seen(2,dst:"10.71.1.2",app:"DCOM"));Assert.True(await Seen(3,dst:"10.71.1.3",app:"DCOM"));}
    [Fact] public async Task Port_135_And_Unstructured_Text_Alone_Are_Not_Proof()
    {for(var i=1;i<8;i++){Assert.False(await Seen(i,dst:$"10.71.1.{i}",app:null));var p=NetworkBatch071075Context.Tcp(i+10,destination:$"10.71.1.{i}",port:135,info:"WMI remote");Assert.False((await _rule.EvaluateAsync(p)).Matched);}}
    [Fact] public async Task Wmi_And_Dcom_Classifications_Do_Not_Combine()
    {Assert.False(await Seen(1,dst:"10.71.1.1"));Assert.False(await Seen(2,dst:"10.71.1.2",app:"DCOM"));Assert.False(await Seen(3,dst:"10.71.1.3"));}
    [Fact] public async Task Wrong_Port_NonSyn_Udp_And_Quic_Are_Rejected()
    {for(var i=1;i<8;i++){Assert.False(await Seen(i,dst:$"10.71.1.{i}",port:445));Assert.False(await Seen(i+10,dst:$"10.71.1.{i}",flags:0x12));Assert.False(await Seen(i+20,dst:$"10.71.1.{i}",protocol:"UDP"));}var q=NetworkBatch071075Context.Tcp(50,port:135,app:"DCOM");q.Record.IsQuic=true;Assert.False((await _rule.EvaluateAsync(q)).Matched);}
    [Fact] public async Task Repeated_Target_Different_Initiator_And_Expired_Window_Do_Not_Accumulate()
    {for(var i=1;i<10;i++)Assert.False(await Seen(i));Assert.False(await Seen(10,dst:"10.71.1.2",src:"10.71.0.11"));Assert.False(await Seen(700,dst:"10.71.1.3"));}
    [Fact] public async Task Cancellation_And_Raw_Info_Privacy_Are_Enforced()
    {using var c=new CancellationTokenSource();c.Cancel();await Assert.ThrowsAnyAsync<OperationCanceledException>(async()=>await _rule.EvaluateAsync(NetworkBatch071075Context.Tcp(1,port:135,app:"WMI"),c.Token));Assert.False(await Seen(2,dst:"10.71.1.2"));Assert.False(await Seen(3,dst:"10.71.1.3"));var p=NetworkBatch071075Context.Tcp(4,destination:"10.71.1.4",port:135,app:"WMI",info:"secret-dcom-credentials");var e=Assert.Single((await _rule.EvaluateAsync(p)).Events);Assert.DoesNotContain("secret-dcom-credentials",e.Description);Assert.DoesNotContain("secret-dcom-credentials",e.Evidence);}
}
