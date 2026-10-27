// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R124AdvancedAccuracyBatchTests
{
    private readonly R124_ExternalRdpExposureAttemptRule _rule = new();
    [Fact] public async Task Outbound_Classified_Rdp_Is_Candidate()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Rdp()))).Matched);
    }
    [Fact] public async Task Inbound_Rdp_Is_Candidate()
    {
        var r = NetworkBatch121125Context.Rdp(); r.Source = "198.51.100.124"; r.Destination = "10.124.1.10";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Only_Rdp_Is_Benign()
    {
        var r = NetworkBatch121125Context.Rdp(); r.Destination = "10.124.1.20";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Source_Port_Only_Is_Not_Rdp_Exposure()
    {
        var r = NetworkBatch121125Context.Rdp(); r.SourcePort = 3389; r.DestinationPort = 443;
        r.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Http_Contradiction_Is_Not_Rdp()
    {
        var r = NetworkBatch121125Context.Rdp(); r.HttpMethod = "GET"; r.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_And_Dns_Contradictions_Fail_Closed()
    {
        var r = NetworkBatch121125Context.Rdp(); r.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
        var d = NetworkBatch121125Context.Rdp(); d.DnsQname = "example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(d))).Matched);
    }
    [Fact] public async Task Info_Secret_Not_Exported()
    {
        const string secret = "rdp-private-124";
        var r = NetworkBatch121125Context.Rdp(); r.Info += " " + secret;
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
    [Fact] public async Task Port_Only_Without_Rdp_Attribution_Fails_Closed()
    {
        var r = NetworkBatch121125Context.Rdp(); r.ApplicationProtocol = "TCP";
        r.ApplicationService = null; r.ProcessName = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }

}
