// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R282AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample()=>NetworkBatch281285Context.Sample();
    private static async Task<RuleEvaluationResult> Evaluate(TrafficRecord r,double seconds=0)
        =>await new R282_VPNLoginFollowedByInternalScanRule().EvaluateAsync(NetworkBatch281285Context.At(r,seconds));
    private static async Task<bool> Hit(TrafficRecord r,double seconds=0)=>(await Evaluate(r,seconds)).Matched;
    [Fact] public async Task Vpn_Udp_Is_Not_Trusted_Outcome(){var r=Sample();r.IsTcp=false;r.IsUdp=true;r.DestinationPort=4500;Assert.False(await Hit(r));}
    [Fact] public async Task Scan_Info_Is_Not_Trusted_Outcome(){var r=Sample();r.Info="authenticated vpn nmap scan";Assert.False(await Hit(r));}
    [Fact] public async Task Vpn_Process_Is_Not_Trusted_Outcome(){var r=Sample();r.ProcessName="openvpn.exe";r.ProcessId=123;Assert.False(await Hit(r));}
    [Fact] public async Task Internal_Smb_Is_Not_Trusted_Outcome(){var r=Sample();r.Destination="10.61.0.99";r.DestinationPort=445;Assert.False(await Hit(r));}
    [Fact] public async Task Internal_Ssh_Is_Not_Trusted_Outcome(){var r=Sample();r.Destination="10.61.0.99";r.DestinationPort=22;Assert.False(await Hit(r));}
    [Fact] public async Task Info_Spoof_Is_Not_Trusted(){var r=Sample();r.Info="R282 verified compromise";Assert.False(await Hit(r));}
    [Fact] public async Task Duplicate_Packet_Does_Not_Accumulate_Evidence(){var r=Sample();var rule=new R282_VPNLoginFollowedByInternalScanRule();Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,1))).Matched);}
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Accumulate_Evidence(){var r=Sample();var rule=new R282_VPNLoginFollowedByInternalScanRule();Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,30))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch281285Context.At(r,1))).Matched);}
    [Fact] public async Task Missing_Source_Fails_Closed(){var r=Sample();r.Source=null;Assert.False(await Hit(r));}
    [Fact] public async Task Contradictory_Udp_Http_Fails_Closed(){var r=Sample();r.IsTcp=false;r.IsUdp=true;Assert.False(await Hit(r));}
    [Fact] public async Task Sensitive_Headers_Are_Not_Emitted(){var r=Sample();r.HttpUri="/callback?code=private-secret";r.HttpRequestHeaders="Authorization: Bearer private-secret";var result=await Evaluate(r);Assert.False(result.Matched);Assert.Empty(result.Events);}
    [Fact] public void Original_Profile_Is_Preserved(){var p=new R282_VPNLoginFollowedByInternalScanRule().PrecisionProfile;Assert.Equal(78,p.MinimumConfidence);Assert.Equal(3,p.Threshold);Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);}
}
