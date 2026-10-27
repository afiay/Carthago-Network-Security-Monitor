// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R125AdvancedAccuracyBatchTests
{
    private readonly R125_ExternalWinrmExposureAttemptRule _rule = new();
    [Fact] public async Task Outbound_Classified_Wsman_Is_Candidate()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Winrm()))).Matched);
    }
    [Fact] public async Task Inbound_Wsman_Is_Candidate()
    {
        var r = NetworkBatch121125Context.Winrm(); r.Source = "198.51.100.125"; r.Destination = "10.125.1.10";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Winrm_Is_Benign()
    {
        var r = NetworkBatch121125Context.Winrm(); r.Destination = "10.125.1.20";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Wrong_Port_With_Https_Classification_Is_Benign()
    {
        var r = NetworkBatch121125Context.Winrm(); r.DestinationPort = 443;
        r.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Port_Only_Http_Get_Is_Not_Winrm()
    {
        var r = NetworkBatch121125Context.Winrm(); r.HttpMethod = "GET"; r.ApplicationService = "HTTP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_And_Quic_Contradictions_Fail_Closed()
    {
        var r = NetworkBatch121125Context.Winrm(); r.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
        var q = NetworkBatch121125Context.Winrm(); q.IsQuic = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(q))).Matched);
    }
    [Fact] public async Task Winrm_Info_Secret_Not_Exported()
    {
        const string secret = "winrm-private-125";
        var r = NetworkBatch121125Context.Winrm(); r.Info += " " + secret;
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
