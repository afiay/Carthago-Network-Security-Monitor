// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R118AdvancedAccuracyBatchTests
{
    private readonly R118_DefaultCredentialIoTAttemptRule _rule = new();

    [Fact] public async Task Single_Parsed_Http_Basic_Default_Pair_Is_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        Assert.Equal(86, _rule.PrecisionProfile.MinimumConfidence);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions");
    }

    [Fact] public async Task Duplicate_Authorization_Is_Ambiguous_Not_A_Login()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpRequestHeaders += "\r\nAuthorization: Basic YWRtaW46YWRtaW4=";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Unattributed_Device_Host_Cannot_Qualify()
    {
        var record = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        record.HttpHost = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_And_Host_Sni_Are_Rejected()
    {
        var udp = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(udp))).Matched);
        var conflict = NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source());
        conflict.Sni = "unrelated.example";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(conflict))).Matched);
    }

    [Fact] public async Task Genuine_Telnet_Default_Pair_Remains_Recognized()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera login: admin:admin";
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
    }

    [Fact] public async Task Telnet_Over_Udp_Cannot_Assert_Default_Pair()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera login: admin:admin";
        record.IsTcp = false; record.IsUdp = true; record.Protocol = "UDP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Default_Credential_Wire_Value_Does_Not_Leak()
    {
        const string token = "YWRtaW46YWRtaW4=";
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Basic(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(token, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(token, StringComparison.Ordinal));
    }
}
