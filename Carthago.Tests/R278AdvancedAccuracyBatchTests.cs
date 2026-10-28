// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R278AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() {
        var r = NetworkBatch276280Context.Sample(); r.HttpUri = "/login";
        r.Info = "invalid password"; return r;
    }
    private static async Task<bool> Hit(TrafficRecord r, double s = 0)
        => (await new R278_PasswordSprayLowAndSlowAcrossAccountsRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r, s))).Matched;
    [Fact] public async Task Failed_Login_Text_Is_Not_Verified_Auth_Failure() =>
        Assert.False(await Hit(Sample()));
    [Fact] public async Task Five_Http_Requests_Are_Not_Five_Failed_Accounts() {
        var r = Sample(); var rule = new R278_PasswordSprayLowAndSlowAcrossAccountsRule();
        for (var i = 0; i < 6; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch276280Context.At(
                NetworkBatch276280Context.Copy(r), i * 60))).Matched);
    }
    [Fact] public async Task Username_Query_Does_Not_Prove_Account_Failure() {
        var r = Sample(); r.HttpUri = "/login?user=alice"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Rotating_Destinations_Are_Not_Account_Cardinality() {
        var r = Sample(); for (var i = 0; i < 5; i++) {
            r.Destination = $"185.220.100.{200 + i}";
            Assert.False(await Hit(NetworkBatch276280Context.Copy(r), i));
        }
    }
    [Fact] public async Task Info_Spoof_Many_Users_Is_Not_Account_Identity() {
        var r = Sample(); r.Info = "password spray 20 failed users";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Count_As_New_Failure() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Count_As_Failures() {
        var r = Sample(); Assert.False(await Hit(r, 20)); Assert.False(await Hit(r, 2));
    }
    [Fact] public async Task Missing_Source_Is_Not_Account_Correlation() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Udp_Http_Does_Not_Create_Failures() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task User_Query_Is_Not_Emitted_As_Failed_Account() {
        var r = Sample(); r.HttpUri = "/login?user=private-user";
        var result = await new R278_PasswordSprayLowAndSlowAcrossAccountsRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r));
        Assert.Empty(result.Events);
    }
    [Fact] public void High_Floor_Mode_And_Five_Event_Threshold_Preserved() {
        var p = new R278_PasswordSprayLowAndSlowAcrossAccountsRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(5, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
