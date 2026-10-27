// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R121AdvancedAccuracyBatchTests
{
    private readonly R121_BACnetDiscoveryFromNonAdminHostRule _rule = new();
    [Fact] public async Task Classified_WhoIs_Broadcast_Is_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch121125Context.At(NetworkBatch121125Context.Bacnet()));
        Assert.True(result.Matched);
    }
    [Fact] public async Task Ordinary_IAm_Broadcast_Does_Not_Trigger()
    {
        var r = NetworkBatch121125Context.Bacnet(); r.Info = "BACnet I-Am announcement";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Multicast_Without_WhoIs_Is_Not_Enough()
    {
        var r = NetworkBatch121125Context.Bacnet(); r.Destination = "239.255.1.1"; r.Info = "BACnet broadcast";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Port_And_Info_Without_Parser_Attribution_Fail_Closed()
    {
        var r = NetworkBatch121125Context.Bacnet(); r.ApplicationProtocol = "UDP"; r.ApplicationService = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Tcp_Or_Http_Cannot_Match()
    {
        var r = NetworkBatch121125Context.Bacnet(); r.IsTcp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
        var h = NetworkBatch121125Context.Bacnet(); h.HttpMethod = "POST";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(h))).Matched);
    }
    [Fact] public async Task Admin_Process_Remains_Suppressed()
    {
        var r = NetworkBatch121125Context.Bacnet(); r.ProcessName = "niagara.exe";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch121125Context.At(r))).Matched);
    }
    [Fact] public async Task Discovery_Payload_Secret_Not_Exported()
    {
        const string secret = "bacnet-private-121";
        var r = NetworkBatch121125Context.Bacnet(); r.Info += " device-token=" + secret;
        var result = await _rule.EvaluateAsync(NetworkBatch121125Context.At(r));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains(secret, StringComparison.Ordinal));
    }
}
