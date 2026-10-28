// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R219AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch216220Context.Request(219);
    private static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => NetworkBatch216220Context.At(r, seconds);
    private static async Task<bool> Hit(TrafficRecord r)
        => (await new R219_TelegramBotApiSendDocumentRule().EvaluateAsync(At(r))).Matched;

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
        var rule = new R219_TelegramBotApiSendDocumentRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(At(r, 1))).Matched);
    }

    [Fact] public async Task Out_Of_Order_Observation_Is_Not_New_Evidence()
    {
        var rule = new R219_TelegramBotApiSendDocumentRule(); var r = Sample();
        Assert.True((await rule.EvaluateAsync(At(r, 10))).Matched);
        var old = Sample(); old.Source = r.Source;
        Assert.False((await rule.EvaluateAsync(At(old, 5))).Matched);
    }

    [Fact] public async Task Independent_Source_Remains_Independent()
    {
        var rule = new R219_TelegramBotApiSendDocumentRule();
        Assert.True((await rule.EvaluateAsync(At(Sample()))).Matched);
        Assert.True((await rule.EvaluateAsync(At(Sample(), 1))).Matched);
    }

    [Fact] public async Task Token_And_Query_Are_Absent_From_Structured_Evidence()
    {
        var r = Sample();
        r.HttpUri += (r.HttpUri!.Contains('?') ? "&" : "?") + "token=superSecretMarker123";
        var result = await new R219_TelegramBotApiSendDocumentRule().EvaluateAsync(At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,
            e => e.Value.Contains("superSecretMarker123", StringComparison.Ordinal)
                || e.Value.Contains("secretSlackWebhookToken", StringComparison.Ordinal)
                || e.Value.Contains("secretDiscordToken", StringComparison.Ordinal)
                || e.Value.Contains("secretTelegramBotToken", StringComparison.Ordinal));
    }

    [Fact] public void Confidence_Floor_And_Default_Mode_Are_Unchanged()
    {
        var profile = new R219_TelegramBotApiSendDocumentRule().PrecisionProfile;
        Assert.Equal(84, profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
    }

    [Fact] public async Task SendMessage_Is_Not_Document_Upload()
    {
        var r = Sample(); r.HttpUri = r.HttpUri!.Replace("sendDocument", "sendMessage");
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Missing_Bot_Secret_Is_Not_Valid_Api_Path()
    {
        var r = Sample(); r.HttpUri = "/bot123456789/sendDocument";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Bot_Client_With_No_Upload_Context_Is_Suppressed()
    {
        var r = Sample(); NetworkBatch216220Context.Small(r);
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Telegram_Desktop_Process_Is_Not_Bot_Exfiltration()
    {
        var r = Sample(); r.ProcessName = "telegram.exe";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task SendDocument_Prefix_Cannot_Impersonate_Endpoint()
    {
        var r = Sample(); r.HttpUri += "Extra";
        Assert.False(await Hit(r));
    }
}
