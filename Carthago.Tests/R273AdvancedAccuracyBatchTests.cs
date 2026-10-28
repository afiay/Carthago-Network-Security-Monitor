// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Carthago.Services;
using Xunit;

namespace Carthago.Tests;

public sealed class R273AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch271275Context.Sample();
    private static async Task<bool> Hit(TrafficRecord r, double seconds = 0)
        => (await new R273_ImpossibleTravelAuthenticationSequenceRule()
            .EvaluateAsync(NetworkBatch271275Context.At(r, seconds))).Matched;
    [Fact] public async Task Packet_GeoIP_Is_Not_Successful_Account_SignIn() {
        var r = Sample(); r.SrcCountry = "France"; r.DstCountry = "Japan";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Country_Labels_In_Info_Are_Not_Authentication() {
        var r = Sample(); r.Info = "impossible travel login France to Japan";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Distant_Latitude_Longitude_Are_Not_Account_Travel() {
        var r = Sample(); r.SrcLat = 48.85; r.SrcLon = 2.35;
        r.DstLat = 35.67; r.DstLon = 139.65; Assert.False(await Hit(r));
    }
    [Fact] public async Task IdP_Sni_Alone_Is_Not_A_SignIn() {
        var r = Sample(); r.Sni = "login.microsoftonline.com"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_User_Parameter_Does_Not_Identify_Authenticated_Account() {
        var r = Sample(); r.HttpUri = "/login?user=alice"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Two_Country_Records_Lack_Same_Account_Correlation() {
        var r = Sample(); r.SrcCountry = "FR"; Assert.False(await Hit(r));
        r = NetworkBatch271275Context.Copy(r); r.SrcCountry = "JP";
        Assert.False(await Hit(r, 10));
    }
    [Fact] public async Task Duplicate_Replay_Does_Not_Create_Authentication() {
        var r = Sample(); Assert.False(await Hit(r)); Assert.False(await Hit(r));
    }
    [Fact] public async Task Out_Of_Order_Records_Do_Not_Create_Travel() {
        var r = Sample(); Assert.False(await Hit(r, 20)); Assert.False(await Hit(r, 1));
    }
    [Fact] public async Task Missing_Source_Is_Not_A_SignIn() {
        var r = Sample(); r.Source = null; Assert.False(await Hit(r));
    }
    [Fact] public async Task Contradictory_Http_And_Dns_Fields_Do_Not_Create_Identity() {
        var r = Sample(); r.HttpMethod = "POST"; r.DnsQname = "login.example.net";
        Assert.False(await Hit(r));
    }
    [Fact] public void High_Floor_Mode_And_Two_Event_Threshold_Preserved() {
        var p = new R273_ImpossibleTravelAuthenticationSequenceRule().PrecisionProfile;
        Assert.Equal(78, p.MinimumConfidence); Assert.Equal(2, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
