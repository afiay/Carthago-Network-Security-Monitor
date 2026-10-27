// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;

public sealed class R133AdvancedAccuracyBatchTests
{
    private readonly R133_BasicAuthenticationOverCleartextRule _rule = new();

    [Fact] public async Task Captured_Basic_Header_Over_Http_Matches()
    {
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Basic()))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "matched_conditions" && x.Value.Contains("basic_authorization_header"));
    }

    [Fact] public async Task Https_Basic_Header_Is_Not_Cleartext()
    {
        var r = NetworkBatch131135Context.Basic();
        r.DestinationPort = 443; r.Protocol = "HTTPS"; r.ApplicationProtocol = "HTTPS"; r.ApplicationService = "HTTPS"; r.Sni = r.HttpHost;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Udp_Or_Port_Only_Attribution_Is_Rejected()
    {
        var udp = NetworkBatch131135Context.Basic(); udp.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(udp))).Matched);
        var port = NetworkBatch131135Context.Basic(); port.ApplicationProtocol = null; port.ApplicationService = null;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(port))).Matched);
    }

    [Fact] public async Task Info_Log_Text_Cannot_Spoof_A_Header()
    {
        var r = NetworkBatch131135Context.Web("/api", true);
        r.Info = "Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Invalid_Base64_And_Decoded_NonCredential_Are_Negative()
    {
        var invalid = NetworkBatch131135Context.Basic();
        invalid.HttpRequestHeaders = "Authorization: Basic ###notbase64";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(invalid))).Matched);
        var plain = NetworkBatch131135Context.Basic();
        plain.HttpRequestHeaders = "Authorization: Basic YWJjZGVmZ2g=";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(plain))).Matched);
    }

    [Fact] public async Task Proxy_Authorization_On_Http_Is_Also_Exposure()
    {
        var r = NetworkBatch131135Context.Basic();
        r.HttpRequestHeaders = "Proxy-Authorization: Basic QWxhZGRpbjpPcGVuU2VzYW1l";
        Assert.True((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Tls_Handshake_Evidence_Overrides_Http_Port()
    {
        var r = NetworkBatch131135Context.Basic(); r.TlsVersion = "TLS 1.3";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch131135Context.At(r))).Matched);
    }

    [Fact] public async Task Credential_And_Secret_Path_Are_Redacted_And_Alert_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Alert, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(86, _rule.PrecisionProfile.MinimumConfidence);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch131135Context.At(NetworkBatch131135Context.Basic("/api/private-secret-133")))).Events);
        Assert.DoesNotContain("QWxhZGRpbjpPcGVuU2VzYW1l", evt.Evidence);
        Assert.DoesNotContain("private-secret-133", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-133", StringComparison.Ordinal));
    }
}
