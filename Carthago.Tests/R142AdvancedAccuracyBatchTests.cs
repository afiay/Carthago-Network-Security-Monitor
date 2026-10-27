// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R142AdvancedAccuracyBatchTests
{
    [Fact] public async Task Distinct_Root_Subject_And_Sni_Are_Candidates()
    {
        var rule = new R142_TlsCertificateSubjectSniMismatchRule();
        var result = await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls()));
        Assert.True(result.Matched);
        Assert.Equal("R142", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Same_Root_Subject_Does_Not_Imply_Mismatch()
    {
        var record = NetworkBatch141145Context.Tls();
        record.CertSubject = "CN=other.example.test";
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Covering_Wildcard_Does_Not_Imply_Mismatch()
    {
        var record = NetworkBatch141145Context.Tls();
        record.CertSubject = "CN=*.example.test";
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task External_Looking_Sni_Cannot_Override_Internal_Socket()
    {
        var record = NetworkBatch141145Context.Tls();
        record.Destination = "10.141.0.50";
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Http_Host_Is_Not_Observed_Tls_Sni()
    {
        var record = NetworkBatch141145Context.Tls();
        record.Sni = null;
        record.HttpHost = "edge.example.test";
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Conflicting_Sni_Authorities_Are_Ambiguous()
    {
        var record = NetworkBatch141145Context.Tls();
        record.TlsSni = "other.example.test";
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_Transport_Does_Not_Qualify()
    {
        var record = NetworkBatch141145Context.Tls();
        NetworkBatch141145Context.AsUdp(record);
        Assert.False((await new R142_TlsCertificateSubjectSniMismatchRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Certificate_Distinguished_Name_Is_Redacted_And_Mode_Unchanged()
    {
        var record = NetworkBatch141145Context.Tls();
        record.CertSubject = "CN=private.other.test";
        var rule = new R142_TlsCertificateSubjectSniMismatchRule();
        var result = await rule.EvaluateAsync(NetworkBatch141145Context.At(record));
        Assert.True(result.Matched);
        var evt = Assert.Single(result.Events);
        Assert.Contains(evt.StructuredEvidence!.Items, item => item.Key == "tls.certSubject" && item.Value == "[REDACTED]");
        Assert.DoesNotContain("private.other.test", evt.Evidence ?? string.Empty);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(72, rule.PrecisionProfile.MinimumConfidence);
    }
}
