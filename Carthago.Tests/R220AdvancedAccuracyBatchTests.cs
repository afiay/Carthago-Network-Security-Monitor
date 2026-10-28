// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R220AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch216220Context.Request(220);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch216220Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R220_PasteServiceHighVolumePostRule().EvaluateAsync(At(r))).Matched;

    [Fact] public async Task Typed_Parser_Attributed_Request_Matches()
        => Assert.True(await Hit(Sample()));

    [Fact] public async Task Unrelated_External_Host_Is_Not_A_Provider()
    {
        var r = Sample();
        NetworkBatch216220Context.ChangeHost(r, "docs.example.net");
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Packet_Info_Cannot_Manufacture_A_Provider_Request()
    {
        var r = Sample();
        NetworkBatch216220Context.ChangeHost(r, "docs.example.net");
        r.HttpUri = "/docs";
        r.Info = "Slack webhook Discord file Telegram sendDocument GCS list paste upload exfil";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Contradictory_Host_Header_Is_Rejected()
    {
        var r = Sample();
        r.HttpRequestHeaders = "Host: attacker.example.net\r\nContent-Length: 70000";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Udp_Transport_Cannot_Carry_Attributed_Http_Request()
    {
        var r = Sample();
        r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Missing_Parsed_Http_Method_Is_Rejected()
    {
        var r = Sample(); r.HttpMethod = null;
        Assert.False(await Hit(r));
    }

    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Match_Again()
    {
        var rule = new R220_PasteServiceHighVolumePostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Observation_Is_Not_New_Evidence()
    {
        var rule = new R220_PasteServiceHighVolumePostRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 10))).Matched);
        var old = Sample(); old.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }

    [Fact] public async Task Independent_Source_Remains_Independent()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }

    [Fact] public async Task Token_And_Query_Are_Absent_From_Structured_Evidence()
    {
        var r = Sample();
        r.HttpUri += (r.HttpUri!.Contains('?') ? "&" : "?") + "token=superSecretMarker123";
        var result = await new R220_PasteServiceHighVolumePostRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("superSecretMarker123", StringComparison.Ordinal)
                || e.Value.Contains("secretSlackWebhookToken", StringComparison.Ordinal)
                || e.Value.Contains("secretDiscordToken", StringComparison.Ordinal)
                || e.Value.Contains("secretTelegramBotToken", StringComparison.Ordinal));
    }

    [Fact] public void Confidence_Floor_And_Default_Mode_Are_Unchanged()
    {
        var profile = new R220_PasteServiceHighVolumePostRule().PrecisionProfile;
        Assert.Equal(82, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }

    [Fact] public async Task Get_Only_Paste_View_Is_Not_A_Post()
    {
        var r = Sample(); r.HttpMethod = "GET";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Empty_Post_With_No_Declared_Body_Is_Rejected()
    {
        var r = Sample(); r.HttpRequestHeaders = "Host: pastebin.com";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Five_Distinct_Small_Posts_Reach_Existing_Threshold()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        var source = "10.220.0.99";
        for (var i = 0; i < 5; i++)
        {
            var r = Sample(); r.Source = source; NetworkBatch216220Context.Small(r);
            Assert.Equal(i == 4, (await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
    [Fact] public async Task Duplicate_Id_Cannot_Inflate_Burst()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        var source = "10.220.0.98";
        var first = Sample(); first.Source = source; NetworkBatch216220Context.Small(first);
        Assert.False((await rule.EvaluateAsync(At(first))).Matched);
        Assert.False((await rule.EvaluateAsync(At(first, 1))).Matched);
        for (var i = 2; i <= 4; i++)
        {
            var r = Sample(); r.Source = source; NetworkBatch216220Context.Small(r);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var fifth = Sample(); fifth.Source = source; NetworkBatch216220Context.Small(fifth);
        Assert.True((await rule.EvaluateAsync(At(fifth, 5))).Matched);
    }
    [Fact] public async Task Separate_Source_Cannot_Complete_Other_Source_Burst()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        for (var i = 0; i < 4; i++)
        {
            var r = Sample(); r.Source = "10.220.0.97"; NetworkBatch216220Context.Small(r);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var other = Sample(); other.Source = "10.220.0.96"; NetworkBatch216220Context.Small(other);
        Assert.False((await rule.EvaluateAsync(At(other, 4))).Matched);
    }
    [Fact] public async Task Expired_Posts_Do_Not_Complete_Window()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        for (var i = 0; i < 4; i++)
        {
            var r = Sample(); r.Source = "10.220.0.95"; NetworkBatch216220Context.Small(r);
            Assert.False((await rule.EvaluateAsync(At(r, i))).Matched);
        }
        var later = Sample(); later.Source = "10.220.0.95"; NetworkBatch216220Context.Small(later);
        Assert.False((await rule.EvaluateAsync(At(later, 1000))).Matched);
    }
    [Fact] public async Task Browser_Requires_Stronger_Burst_Than_Automation()
    {
        var rule = new R220_PasteServiceHighVolumePostRule();
        for (var i = 0; i < 6; i++)
        {
            var r = Sample(); r.Source = "10.220.0.94"; r.ProcessName = "chrome.exe";
            NetworkBatch216220Context.Small(r);
            Assert.Equal(i == 5, (await rule.EvaluateAsync(At(r, i))).Matched);
        }
    }
}
