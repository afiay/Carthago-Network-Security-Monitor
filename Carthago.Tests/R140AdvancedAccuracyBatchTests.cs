// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Xunit;

namespace Carthago.Tests;
public sealed class R140AdvancedAccuracyBatchTests
{
    private readonly R140_SuspiciousCertificateIssuerPatternRule _rule = new();
    [Fact] public async Task Exact_Mitmproxy_Issuer_Cn_Matches()
    {
        Assert.True((await _rule.EvaluateAsync(NetworkBatch136140Context.At(
            NetworkBatch136140Context.Tls(issuer: "CN=mitmproxy")))).Matched);
    }
    [Fact] public async Task Public_Certificate_Authority_Is_Benign()
    {
        var r = NetworkBatch136140Context.Tls(issuer: "CN=GlobalSign Atlas R3 DV TLS CA 2025 Q1");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Keyword_Substring_In_Legitimate_Issuer_Is_Not_Enough()
    {
        var r = NetworkBatch136140Context.Tls(issuer: "CN=Notmitmproxy Corporation");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Suspicious_Ou_Without_Suspicious_Cn_Is_Not_Issuer_Identity()
    {
        var r = NetworkBatch136140Context.Tls(issuer: "OU=mitmproxy, CN=Public Authority");
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_Issuer_Claim_Is_Not_Parsed_Certificate()
    {
        var r = NetworkBatch136140Context.Tls(issuer: "");
        r.Info = "issuer CN=mitmproxy";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_And_Missing_Tcp_Are_Rejected()
    {
        var a = NetworkBatch136140Context.Tls(issuer: "CN=mitmproxy"); a.IsUdp = true;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(a))).Matched);
        var b = NetworkBatch136140Context.Tls(issuer: "CN=mitmproxy"); b.IsTcp = false;
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(b))).Matched);
    }
    [Fact] public async Task Contradictory_Http_Request_Metadata_Is_Rejected()
    {
        var r = NetworkBatch136140Context.Tls(issuer: "CN=mitmproxy"); r.HttpMethod = "GET";
        Assert.False((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Matched);
    }
    [Fact] public async Task Issuer_Distinguished_Name_Is_Redacted_And_Shadow_Unchanged()
    {
        Assert.Equal(RuleRuntimeMode.Shadow, _rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, _rule.PrecisionProfile.MinimumConfidence);
        var r = NetworkBatch136140Context.Tls(issuer: "CN=mitmproxy, O=private-secret-140");
        var evt = Assert.Single((await _rule.EvaluateAsync(NetworkBatch136140Context.At(r))).Events);
        Assert.DoesNotContain("private-secret-140", evt.Evidence);
        Assert.DoesNotContain(evt.StructuredEvidence!.Items, x => x.Value.Contains("private-secret-140", StringComparison.Ordinal));
    }
}
