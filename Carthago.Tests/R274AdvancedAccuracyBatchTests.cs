// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R274AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.Sample();
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await new R274_MFAPushFatiguePatternRule()
            .EvaluateAsync(NetworkBatch271275Context.At(r, seconds))).Matched;
    [Fact] public async Task Info_Mfa_Denied_Is_Not_Trusted_Push_Outcome() {
        var r = Sample(); r.Info = "MFA push denied"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Repeated_Packets_Are_Not_Distinct_Push_Ids() {
        var r = Sample(); r.Info = "MFA prompt";
        for (var i = 0; i < 5; i++)
            Assert.False(await Hit(NetworkBatch271275Context.Copy(r), i));
    }
    [Fact] public async Task Duo_Host_Is_Not_Proof_Of_Prompt() {
        var r = Sample(); r.Sni = "api.duo.com"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Mfa_Route_Is_Not_Push_Outcome() {
        var r = Sample(); r.HttpMethod = "GET"; r.HttpUri = "/mfa/push";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Process_Label_Does_Not_Prove_Fatigue() {
        var r = Sample(); r.ProcessName = "duo-push.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task User_Code_Query_Does_Not_Prove_Mfa_Denial() {
        var r = Sample(); r.HttpUri = "/mfa?user_code=123456";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Cannot_Create_Mfa_Events() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Create_Fatigue() {
        var r = Sample(); Assert.False(await Hit(r, 20)); Assert.False(await Hit(r, 2));
    }
    [Fact] public async Task Contradictory_Transport_Is_Not_Trusted_Auth() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Null_Source_Is_Not_Trusted_Auth() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public void High_Floor_Mode_And_Three_Prompt_Threshold_Preserved() {
        var p = new R274_MFAPushFatiguePatternRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(3, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
