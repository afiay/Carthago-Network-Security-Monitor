// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R117AdvancedAccuracyBatchTests
{
    private readonly R117_TelnetLoginAttemptToIoTDeviceRule _rule = new();

    [Fact] public async Task Attributed_Telnet_Login_Prompt_On_Device_Is_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source())));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions" && item.Value.Contains("authentication_prompt"));
    }

    [Fact] public async Task Bare_Telnet_Session_Has_No_Authentication_Evidence()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "telnet connection established";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Unstructured_Username_Prose_Is_Not_A_Prompt()
    {
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera username documentation only";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Wrong_Port_Or_Unclassified_Telnet_Claim_Is_Rejected()
    {
        var port = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        port.DestinationPort = 2323;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(port))).Matched);
        var unclassified = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        unclassified.ApplicationService = "HTTP"; unclassified.ApplicationProtocol = "TCP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(unclassified))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_And_Http_Do_Not_Qualify()
    {
        var udp = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(udp))).Matched);
        var http = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        http.HttpMethod = "POST";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(http))).Matched);
    }

    [Fact] public async Task Distinct_Device_Targets_Stay_Independent()
    {
        var source = NetworkBatch116120Context.Source();
        var first = NetworkBatch116120Context.Telnet(source, "10.40.1.60");
        var second = NetworkBatch116120Context.Telnet(source, "10.40.1.61");
        Assert.True((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(first, 0))).Matched);
        Assert.True((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(second, 1))).Matched);
    }

    [Fact] public async Task Login_Password_Transcript_Is_Not_Persisted()
    {
        const string secret = "telnet-secret-117";
        var record = NetworkBatch116120Context.Telnet(NetworkBatch116120Context.Source());
        record.Info = "camera telnet login: admin password: " + secret;
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(secret, StringComparison.Ordinal));
    }
}
