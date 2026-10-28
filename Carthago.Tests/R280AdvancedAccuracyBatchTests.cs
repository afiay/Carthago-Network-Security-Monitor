// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R280AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() {
        var r = NetworkBatch276280Context.Sample(); r.SrcCountry = "FR";
        r.HttpRequestHeaders = "Cookie: sessionid=secret-marker"; return r;
    }
    private static async Task<bool> Hit(TrafficRecord r, double s = 0)
        => (await new R280_SessionTokenReplayAcrossGeographiesRule()
            .EvaluateAsync(NetworkBatch276280Context.At(r, s))).Matched;
    [Fact] public async Task Cookie_Text_Is_Not_Verified_Token_Replay() =>
        Assert.False(await Hit(Sample()));
    [Fact] public async Task Two_Countries_Are_Not_One_Authenticated_Session() {
        var r = Sample(); Assert.False(await Hit(r));
        r = NetworkBatch276280Context.Copy(r); r.SrcCountry = "JP";
        Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Sni_And_GeoIP_Are_Not_Session_Audit() {
        var r = Sample(); r.Sni = "login.microsoftonline.com";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Token_Replay_Info_Label_Is_Not_Trusted() {
        var r = Sample(); r.Info = "same session token replay across countries";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Header_Cookie_Is_Not_Verified_Session_Fingerprint() {
        var r = Sample(); r.HttpRequestHeaders = "Cookie: sessionid=token-123";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Is_Not_Distinct_Session_Use() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Out_Of_Order_Packets_Do_Not_Prove_Replay() {
        var r = Sample(); Assert.False(await Hit(r, 30)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Missing_Source_Cannot_Identify_Session() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Transport_Is_Not_Session_Reuse() {
        var r = Sample(); r.IsUdp = true; Assert.False(await Hit(r));
    }
    [Fact] public async Task Raw_Cookie_Is_Not_Emitted_As_Session_Evidence() {
        var result = await new R280_SessionTokenReplayAcrossGeographiesRule()
            .EvaluateAsync(NetworkBatch276280Context.At(Sample()));
        Assert.Empty(result.Events);
    }
    [Fact] public void High_Floor_Mode_And_Two_Event_Threshold_Preserved() {
        var p = new R280_SessionTokenReplayAcrossGeographiesRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(2, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
