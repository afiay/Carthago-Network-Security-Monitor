// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;
public sealed class R139AdvancedAccuracyBatchTests
{
    private readonly R139_WeakTlsVersionObservedRule _rule = new();
    [Fact] public async Task Negotiated_Tls10_Matches()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Tls(version: "TLS 1.0")))).Matched);
    }
    [Fact] public async Task Tls11_And_Sslv3_Are_Recognized()
    {
        foreach (var version in new[] { "TLS 1.1", "SSLv3" })
            Assert.True((await new R139_WeakTlsVersionObservedRule().EvaluateAsync(
                NetworkBatch136140Context.At(NetworkBatch136140Context.Tls(version: version)))).Matched);
    }
    [Fact] public async Task Modern_Tls12_And_Tls13_Are_Not_Weak()
    {
        foreach (var version in new[] { "TLS 1.2", "TLS 1.3" })
            Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Tls(version: version)))).Matched);
    }
    [Fact] public async Task Client_Offer_Text_Is_Not_Negotiated_Version()
    {
        var r = NetworkBatch136140Context.Tls(version: "TLS 1.0 offered in ClientHello");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Port_443_And_Info_Only_Cannot_Claim_Weak_Tls()
    {
        var r = NetworkBatch136140Context.Tls(version: ""); r.Info = "weak TLS 1.0";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Quic_And_Missing_Tcp_Are_Not_Tls_Over_Tcp()
    {
        var a = NetworkBatch136140Context.Tls(version: "TLS 1.0"); a.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Tls(version: "TLS 1.0"); b.IsQuic = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
        var c = NetworkBatch136140Context.Tls(version: "TLS 1.0"); c.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(c))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Application_Label_Is_Rejected()
    {
        var r = NetworkBatch136140Context.Tls(version: "TLS 1.0"); r.ApplicationProtocol = "HTTP";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Normalized_Weak_Version_And_Alert_Confidence_Remain()
    {
        Assert.Equal(RuleRuntimeMode.Alert, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(88, _rule.PrecisionProfile.MinimumConfidence);
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Tls(version: "TLSv1.0")))).Events);
        Assert.Contains(evt.StructuredEvidence!.Items, x => x.Key == "tls.version" && x.Value == "TLS 1.0");
    }
}
