// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class R268AdvancedAccuracyBatchTests
{
    private static TrafficRecord Sample() => NetworkBatch266270Context.Sample(268);
    private static RuleEvaluationContext At(TrafficRecord r, double s = 0) => NetworkBatch266270Context.At(r, s);
    private static async Task<bool> Hit(R268_DnsOrHttpFromScriptInterpreterRule rule, TrafficRecord r, double s = 0)
        => (await rule.EvaluateAsync(At(r, s))).Matched;
    private static TrafficRecord Dns() {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; r.Protocol = "UDP";
        r.DestinationPort = 53; r.ApplicationProtocol = "DNS"; r.HttpMethod = null;
        r.HttpHost = null; r.HttpUri = null; r.DnsQname = "example.net"; r.DnsQtype = "A";
        return r;
    }
    [Fact] public async Task Parsed_Cleartext_Http_From_Exact_Interpreter_Matches() =>
        Assert.True(await Hit(new(), Sample()));
    [Fact] public async Task Typed_Dns_Query_From_Interpreter_Matches() =>
        Assert.True(await Hit(new(), Dns()));
    [Fact] public async Task Https_Port_Without_Parsed_Http_Does_Not_Match() {
        var r = Sample(); r.DestinationPort = 443; r.HttpMethod = null;
        r.HttpHost = null; r.HttpUri = null; r.ApplicationProtocol = null;
        r.TlsVersion = "TLS1.3"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Port_53_Without_Typed_Dns_Is_Rejected() {
        var r = Dns(); r.DnsQname = null; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Interpreter_Substring_Is_Rejected() {
        var r = Sample(); r.ProcessName = "notpython.exe"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Packet_Info_Cannot_Invent_Interpreter() {
        var r = Sample(); r.ProcessName = null; r.Info = "python DNS"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Missing_Pid_Is_Rejected() {
        var r = Sample(); r.ProcessId = 0; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Internal_Destination_Is_Rejected() {
        var r = Sample(); r.Destination = "10.61.0.20"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Udp_Http_Contradiction_Is_Rejected() {
        var r = Sample(); r.IsTcp = false; r.IsUdp = true; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Dns_Response_Is_Not_Interpreter_Query() {
        var r = Dns(); r.DnsIsResponse = true; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Invalid_Dns_Name_Is_Rejected() {
        var r = Dns(); r.DnsQname = "bad name!"; Assert.False(await Hit(new(), r));
    }
    [Fact] public async Task Replay_Id_Is_Rejected() {
        var rule = new R268_DnsOrHttpFromScriptInterpreterRule(); var r = Sample();
        Assert.True(await Hit(rule, r)); Assert.False(await Hit(rule, r, 1));
    }
    [Fact] public async Task Sensitive_Info_And_Process_Path_Are_Redacted() {
        var r = Sample(); r.ProcessName = @"C:\secret-marker\python.exe"; r.Info = "secret-marker";
        var evt = Assert.Single((await new R268_DnsOrHttpFromScriptInterpreterRule().EvaluateAsync(At(r))).Events);
        Assert.DoesNotContain("secret-marker", evt.Evidence ?? "", StringComparison.Ordinal);
    }
    [Fact] public void Confidence_Mode_And_Threshold_Unchanged() {
        var p = new R268_DnsOrHttpFromScriptInterpreterRule().PrecisionProfile;
        Assert.Equal(82, p.MinimumConfidence); Assert.Equal(1, p.Threshold);
        Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
