// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R143AdvancedAccuracyBatchTests
{
    [Fact] public async Task Wildcard_On_Management_Tls_Port_Matches()
    {
        var result = await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(
            NetworkBatch141145Context.At(NetworkBatch141145Context.Wildcard()));
        Assert.True(result.Matched);
        Assert.Equal("R143", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Https_Wildcard_On_Ordinary_Port_Does_Not_Match()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.DestinationPort = 443;
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Concrete_Certificate_Subject_Does_Not_Match()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.CertSubject = "CN=admin.example.test";
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Missing_Tcp_Flag_Is_Not_Silent_TLS_Attribution()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.IsTcp = false;
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Wildcard_String_In_Info_Is_Not_Certificate_Metadata()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.CertSubject = null;
        record.Info = "cert subject CN=*.example.test";
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Quic_Transport_Is_Not_Tls_Over_Tcp()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.IsQuic = true;
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Syn_Only_Is_Not_Presented_Certificate_Evidence()
    {
        var record = NetworkBatch141145Context.Wildcard();
        record.TcpFlags = 0x02;
        Assert.False((await new R143_WildcardCertificateOnSensitiveServiceRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Wildcard_Name_Remains_Private_And_Shadowed()
    {
        var rule = new R143_WildcardCertificateOnSensitiveServiceRule();
        var result = await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Wildcard()));
        var evt = Assert.Single(result.Events);
        Assert.Contains(evt.StructuredEvidence!.Items, item => item.Key == "tls.certSubject" && item.Value == "[REDACTED]");
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
        Assert.Equal(70, rule.PrecisionProfile.MinimumConfidence);
    }
}
