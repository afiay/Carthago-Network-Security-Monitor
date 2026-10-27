// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R145AdvancedAccuracyBatchTests
{
    [Fact] public async Task Three_Distinct_Consistent_Sessions_Reach_Threshold()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        RuleEvaluationResult? last = null;
        for (var i = 0; i < 3; i++)
            last = await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 20));
        Assert.True(last!.Matched);
        Assert.Equal("R145", Assert.Single(last.Events).RuleId);
        Assert.Equal(74, rule.PrecisionProfile.MinimumConfidence);
    }

    [Fact] public async Task Duplicate_Id_Does_Not_Add_Observation()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        var first = NetworkBatch141145Context.Tls();
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(first))).Matched);
        var duplicate = NetworkBatch141145Context.Tls();
        duplicate.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(duplicate, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), 20))).Matched);
    }

    [Fact] public async Task Other_Client_Cannot_Complete_Window()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        for (var i = 0; i < 2; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 10))).Matched);
        var record = NetworkBatch141145Context.Tls();
        record.Source = "10.145.0.20";
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(record, 20))).Matched);
    }

    [Fact] public async Task Different_Certificate_Interval_Cannot_Masquerade_As_Repeat()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        for (var i = 0; i < 2; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 10))).Matched);
        var record = NetworkBatch141145Context.Tls();
        record.CertValidTo = record.CertValidTo!.Value.AddDays(1);
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(record, 20))).Matched);
    }

    [Fact] public async Task Ninety_Day_Automated_Certificate_Does_Not_Match()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        for (var i = 0; i < 3; i++)
        {
            var record = NetworkBatch141145Context.Tls();
            record.CertValidTo = record.CertValidFrom!.Value.AddDays(90);
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(record, i * 10))).Matched);
        }
    }

    [Fact] public async Task Browser_Sessions_Remain_Benign()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        for (var i = 0; i < 3; i++)
        {
            var record = NetworkBatch141145Context.Tls();
            record.ProcessName = "firefox.exe";
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(record, i * 10))).Matched);
        }
    }

    [Fact] public async Task Missing_Dates_Cannot_Be_Short_Certificate_Evidence()
    {
        var record = NetworkBatch141145Context.Tls();
        record.CertValidTo = null;
        Assert.False((await new R145_ShortLivedCertificateWithNewSniRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Udp_And_Http_Metadata_Contradictions_Cannot_Qualify()
    {
        var rule = new R145_ShortLivedCertificateWithNewSniRule();
        var udp = NetworkBatch141145Context.Tls();
        NetworkBatch141145Context.AsUdp(udp);
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(udp))).Matched);
        var conflicting = NetworkBatch141145Context.Tls();
        conflicting.HttpMethod = "GET";
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(conflicting, 10))).Matched);
        Assert.Equal(RuleRuntimeMode.Shadow, rule.PrecisionProfile.DefaultMode);
    }
}
