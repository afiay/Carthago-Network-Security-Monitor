// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R279AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() {
        var r = NetworkBatch276280Context.Sample(); r.HttpUri = "/login";
        r.HttpUserAgent = "Mozilla/5.0"; return r;
    }
    private static async Task<bool> Hit(TrafficRecord r, double s = 0)
        => (await new R279_CredentialStuffingRotatingUserAgentRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r, s))).Matched;
    [Fact] public async Task Login_Path_And_User_Agent_Are_Not_Auth_Failure() =>
        Assert.False(await Hit(Sample()));
    [Fact] public async Task Five_Rotating_User_Agents_Without_Failures_Do_Not_Match() {
        var r = Sample(); var rule = new R279_CredentialStuffingRotatingUserAgentRule();
        for (var i = 0; i < 6; i++) {
            var item = NetworkBatch276280Context.Copy(r); item.HttpUserAgent = $"Browser/{i}";
            Assert.False((await rule.EvaluateAsync(NetworkBatch276280Context.At(item, i))).Matched);
        }
    }
    [Fact] public async Task Info_Claiming_Stuffing_Is_Not_Trusted_Outcome() {
        var r = Sample(); r.Info = "credential stuffing login failure";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_403_Is_Not_Account_Authentication_Failure() {
        var r = Sample(); r.Info = "HTTP 403"; Assert.False(await Hit(r));
    }
    [Fact] public async Task User_Agent_Only_Is_Not_Auth_Event() {
        var r = Sample(); r.HttpUri = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Does_Not_Imply_Multiple_Accounts() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_User_Agents_Do_Not_Imply_Stuffing() {
        var r = Sample(); Assert.False(await Hit(r, 20)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Independent_Sources_Are_Not_Correlated_Accounts() {
        var r = Sample(); Assert.False(await Hit(r));
        r.Source = "10.61.0.11"; Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Contradictory_Udp_Http_Is_Not_Trusted_Auth() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Raw_User_Agent_Is_Not_Emitted_As_Credential_Evidence() {
        var r = Sample(); r.HttpUserAgent = "secret-credential-marker";
        var result = await new R279_CredentialStuffingRotatingUserAgentRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r));
        Assert.Empty(result.Events);
    }
    [Fact] public void High_Floor_Mode_And_Five_Event_Threshold_Preserved() {
        var p = new R279_CredentialStuffingRotatingUserAgentRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(5, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
