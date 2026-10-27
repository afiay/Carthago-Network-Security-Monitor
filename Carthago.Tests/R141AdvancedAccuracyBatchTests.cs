// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R141AdvancedAccuracyBatchTests
{
    [Fact] public async Task Three_Independent_Attributed_Sessions_Reach_Threshold()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        RuleEvaluationResult? last = null;
        for (var i = 0; i < 3; i++)
            last = await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 20));
        Assert.True(last!.Matched);
        Assert.Equal("R141", Assert.Single(last.Events).RuleId);
        Assert.Equal(74, rule.PrecisionProfile.MinimumConfidence);
    }

    [Fact] public async Task Duplicate_Packet_Id_Cannot_Fill_Window()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        var first = NetworkBatch141145Context.Tls();
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(first))).Matched);
        var replay = NetworkBatch141145Context.Tls();
        replay.Id = first.Id;
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(replay, 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), 20))).Matched);
        Assert.True((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), 30))).Matched);
    }

    [Fact] public async Task Different_Sources_Do_Not_Merge_Bursts()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        for (var i = 0; i < 2; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 10))).Matched);
        var other = NetworkBatch141145Context.Tls();
        other.Source = "10.141.0.11";
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(other, 20))).Matched);
    }

    [Fact] public async Task Different_Sni_Cannot_Complete_Same_Window()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        for (var i = 0; i < 2; i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(NetworkBatch141145Context.Tls(), i * 10))).Matched);
        var other = NetworkBatch141145Context.Tls();
        other.Sni = "another.example.test";
        Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(other, 20))).Matched);
    }

    [Fact] public async Task Contradictory_Udp_Transport_Is_Not_TLS_Session()
    {
        var record = NetworkBatch141145Context.Tls();
        NetworkBatch141145Context.AsUdp(record);
        Assert.False((await new R141_NewSniWithRareTlsFingerprintRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Missing_Observed_Fingerprint_Is_Not_Inferred_From_Text()
    {
        var record = NetworkBatch141145Context.Tls();
        record.Ja4 = null;
        record.Info = "ja4-unique-client";
        Assert.False((await new R141_NewSniWithRareTlsFingerprintRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Conflicting_Handshake_Sni_Fields_Are_Rejected()
    {
        var record = NetworkBatch141145Context.Tls();
        record.TlsSni = "different.example.test";
        Assert.False((await new R141_NewSniWithRareTlsFingerprintRule().EvaluateAsync(NetworkBatch141145Context.At(record))).Matched);
    }

    [Fact] public async Task Repeated_Browser_Sessions_Are_Benign()
    {
        var rule = new R141_NewSniWithRareTlsFingerprintRule();
        for (var i = 0; i < 4; i++)
        {
            var record = NetworkBatch141145Context.Tls();
            record.ProcessName = "chrome.exe";
            Assert.False((await rule.EvaluateAsync(NetworkBatch141145Context.At(record, i * 10))).Matched);
        }
    }
}
