// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules.CloudSaas;
using Xunit;

namespace Carthago.Tests;

public sealed class R111AdvancedAccuracyBatchTests
{
    private readonly R111_PasteSiteFileDropServiceEgressRule _rule = new();

    [Fact] public async Task Typed_Post_To_File_Drop_Emits_Provider_Evidence()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source());
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Equal("R111", evt.RuleId);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "matched_conditions");
    }

    [Fact] public async Task Large_Get_Read_Does_Not_Become_Upload()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source(),
            method: "GET", uri: "/public/paste", bytes: 8_000_000, process: "chrome.exe");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Tiny_Post_With_Info_Only_Upload_Claim_Is_Benign()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source(),
            uri: "/view", bytes: 1024, process: "chrome.exe", info: "upload secret archive");
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Contradictory_Sni_And_Http_Host_Are_Rejected()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source());
        c.Record.Sni = "unrelated.example";
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }

    [Fact] public async Task Udp_Or_Contradictory_Application_Classification_Is_Rejected()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source());
        c.Record.IsTcp = false; c.Record.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
        var other = NetworkBatch111115Context.Web(1, NetworkBatch111115Context.Source());
        other.Record.ApplicationProtocol = "DNS";
        Assert.False((await _rule.EvaluateAsync(other)).Matched);
    }

    [Fact] public async Task Upload_Query_Secret_Is_Redacted_From_Alert()
    {
        const string secret = "private-upload-token-111";
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source(),
            uri: "/upload?access_token=" + secret);
        var result = await _rule.EvaluateAsync(c);
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Description);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
        Assert.Contains(evt.StructuredEvidence.Items, x => x.Key == "http.uri" && x.Value == "[redacted]");
    }

    [Fact] public async Task Empty_Record_Identity_Cannot_Produce_Egress_Alert()
    {
        var c = NetworkBatch111115Context.Web(0, NetworkBatch111115Context.Source());
        c.Record.Id = Guid.Empty;
        Assert.False((await _rule.EvaluateAsync(c)).Matched);
    }
}
