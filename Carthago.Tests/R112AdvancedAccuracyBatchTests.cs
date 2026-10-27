// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;

namespace Carthago.Tests;

public sealed class R112AdvancedAccuracyBatchTests
{
    private readonly R112_SaaSExportLikeTrafficPatternRule _rule = new();

    private static Carthago.Engine.Rules.RuleEvaluationContext Export(int seconds, string source,
        string uri = "/services/data/jobs/export", int bytes = 900_000,
        string process = "powershell.exe", string method = "POST")
        => NetworkBatch111115Context.Web(seconds, source, host: "acme.salesforce.com",
            method: method, uri: uri, bytes: bytes, process: process);

    [Fact] public async Task Typed_Bulk_Export_Post_Matches()
    {
        var result = await _rule.EvaluateAsync(Export(0, NetworkBatch111115Context.Source()));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            x => x.Key == "matched_conditions");
    }

    [Fact] public async Task Large_Get_Export_Download_Is_Not_An_Upload()
    {
        Assert.False((await _rule.EvaluateAsync(Export(0, NetworkBatch111115Context.Source(),
            method: "GET", bytes: 12_000_000, process: "chrome.exe"))).Matched);
    }

    [Fact] public async Task Query_Parameter_Cannot_Forge_Export_Endpoint()
    {
        Assert.False((await _rule.EvaluateAsync(Export(0, NetworkBatch111115Context.Source(),
            uri: "/services/data/users?export=true"))).Matched);
    }

    [Fact] public async Task Info_Only_Export_Claim_Cannot_Seed_Repetition()
    {
        var source = NetworkBatch111115Context.Source();
        for (var i = 0; i < 4; i++)
        {
            var c = Export(i * 10, source, uri: "/services/data/users", bytes: 900_000);
            c.Record.Info = "bulk export backup";
            Assert.False((await _rule.EvaluateAsync(c)).Matched);
        }
    }

    [Fact] public async Task Info_Only_Upload_Hint_Does_Not_Promote_Tiny_Export_Post()
    {
        var c = Export(0, NetworkBatch111115Context.Source(),
            bytes: 10_000, process: "chrome.exe");
        c.Record.Info = "upload file multipart";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Duplicate_Packet_Identity_Does_Not_Fill_Repeat_Window()
    {
        var c = Export(0, NetworkBatch111115Context.Source(), bytes: 10_000,
            process: "chrome.exe");
        for (var i = 0; i < 8; i++)
            Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Independent_Repeated_Export_Actions_Can_Reach_Threshold()
    {
        var source = NetworkBatch111115Context.Source();
        Assert.False((await _rule.EvaluateAsync(Export(0, source,
            bytes: 10_000, process: "chrome.exe"))).Matched);
        var result = await _rule.EvaluateAsync(Export(30, source,
            bytes: 10_000, process: "chrome.exe"));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            x => x.Key == "count" && x.Value == "2");
    }

    [Fact] public async Task Encoded_Export_Path_Is_Recognized_But_Token_Is_Not_Exposed()
    {
        const string secret = "tenant-private-token-112";
        var result = await _rule.EvaluateAsync(Export(0, NetworkBatch111115Context.Source(),
            uri: "/services/data/%65xport?token=" + secret));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Description);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
        Assert.Contains(evt.StructuredEvidence.Items, x => x.Key == "http.uri" && x.Value == "[redacted]");
    }

    [Fact] public async Task Sni_Conflict_And_Exported_Filename_Do_Not_Qualify()
    {
        var bad = Export(0, NetworkBatch111115Context.Source());
        bad.Record.Sni = "other.example";
        Assert.False((await _rule.EvaluateAsync(bad)).Matched);
        Assert.False((await _rule.EvaluateAsync(Export(0, NetworkBatch111115Context.Source(),
            uri: "/services/data/exported.csv"))).Matched);
    }
}
