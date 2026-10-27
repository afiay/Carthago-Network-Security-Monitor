// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules.IotOt;
using Xunit;

namespace Carthago.Tests;

public sealed class R120AdvancedAccuracyBatchTests
{
    private readonly R120_ModbusTrafficOutsideApprovedSegmentRule _rule = new();

    [Fact] public async Task Classified_Cross_Segment_Modbus_Write_Is_Candidate()
    {
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(
            NetworkBatch116120Context.Modbus()));
        Assert.True(result.Matched);
        Assert.Contains(Assert.Single(result.Events).StructuredEvidence!.Items,
            item => item.Key == "matched_conditions" && item.Value.Contains("write_like_function"));
    }

    [Fact] public async Task Same_Segment_Modbus_Read_Remains_Benign()
    {
        var record = NetworkBatch116120Context.Modbus("10.20.0.10", "10.20.0.20");
        record.Info = "modbus read holding registers function 3";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Cross_Segment_Read_Without_Write_Intent_Is_Benign()
    {
        var record = NetworkBatch116120Context.Modbus();
        record.Info = "modbus read holding registers function 3";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Info_Only_Modbus_Claim_Cannot_Replace_Protocol()
    {
        var record = NetworkBatch116120Context.Modbus();
        record.Protocol = "TCP"; record.ApplicationProtocol = "TCP";
        record.ApplicationService = "HTTPS";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Udp_And_Http_Contradictions_Do_Not_Qualify()
    {
        var udp = NetworkBatch116120Context.Modbus();
        udp.IsTcp = false; udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(udp))).Matched);
        var http = NetworkBatch116120Context.Modbus();
        http.HttpMethod = "POST";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(http))).Matched);
    }

    [Fact] public async Task Classified_External_Modbus_Boundary_Still_Qualifies()
    {
        var record = NetworkBatch116120Context.Modbus("10.20.0.10", "198.51.100.20");
        record.Info = "modbus read holding registers function 3";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record))).Matched);
    }

    [Fact] public async Task Modbus_Payload_Secrets_Never_Appear_In_Alert()
    {
        const string secret = "modbus-private-value-120";
        var record = NetworkBatch116120Context.Modbus();
        record.Info += " value=" + secret;
        var result = await _rule.EvaluateAsync(NetworkBatch116120Context.Context(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.DoesNotContain(secret, evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items,
            item => item.Value.Contains(secret, StringComparison.Ordinal));
    }
}
