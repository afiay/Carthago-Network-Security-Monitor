// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;
public sealed class R138AdvancedAccuracyBatchTests
{
    private readonly R138_SelfSignedCertificateToExternalHostRule _rule = new();
    [Fact] public async Task Identical_Certificate_Distinguished_Names_At_External_Ip_Match()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch136140Context.At(NetworkBatch136140Context.Tls()))).Matched);
    }
    [Fact] public async Task Different_Issuer_And_Subject_Are_Not_Self_Issued()
    {
        var r = NetworkBatch136140Context.Tls("CN=Public CA", "CN=service.example.test");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Internal_Destination_Is_Not_External()
    {
        var r = NetworkBatch136140Context.Tls(); r.Destination = "10.138.0.20";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task External_Sni_Cannot_Override_Private_Destination()
    {
        var r = NetworkBatch136140Context.Tls(); r.Destination = "192.168.1.2"; r.Sni = "external.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_And_Missing_Tcp_Are_Rejected()
    {
        var a = NetworkBatch136140Context.Tls(); a.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Tls(); b.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
    }
    [Fact] public async Task Info_Only_SelfSigned_Claim_Is_Not_Certificate_Evidence()
    {
        var r = NetworkBatch136140Context.Tls(); r.CertIssuer = null; r.CertSubject = null;
        r.Info = "self-signed CN=stage.example.test";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Equal_Common_Names_With_Different_Organization_Are_Not_Equal_Dns()
    {
        var r = NetworkBatch136140Context.Tls("CN=edge.example.test, O=Issuer",
            "CN=edge.example.test, O=Subject");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Certificate_Names_Are_Redacted_And_Shadow_Preserved()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, _rule.PrecisionProfile.MinimumConfidence);
        var r = NetworkBatch136140Context.Tls("CN=private-secret-138", "CN=private-secret-138");
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Events);
        Assert.DoesNotContain("private-secret-138", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-138", StringComparison.Ordinal));
    }
}
