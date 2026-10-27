// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R146AdvancedAccuracyBatchTests
{
    [Fact] public async Task Twelve_Independent_Tls_Failure_Summaries_Trigger()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        RuleEvaluationResult? last = null;
        for (int i = 0; i < 12; i++)
        {
            var r = NetworkBatch146150Context.Tls(); r.Info = "tls alert handshake failure";
            last = await rule.EvaluateAsync(NetworkBatch146150Context.At(r, i * 5));
        }
        Assert.True(last!.Matched);
        Assert.Equal("R146", Assert.Single(last.Events).RuleId);
    }

    [Fact] public async Task Duplicate_Identifiers_Do_Not_Complete_Failure_Window()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        var first = NetworkBatch146150Context.Tls(); first.Info = "handshake failure";
        var id = first.Id;
        for (var i = 0; i < 12; i++)
        {
            var r = NetworkBatch146150Context.Tls(); r.Id = id; r.Info = "handshake failure";
            Assert.False((await rule.EvaluateAsync(NetworkBatch146150Context.At(r, i * 3))).Matched);
        }
    }

    [Fact] public async Task Distinct_Destinations_Never_Combine_Failures()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        for (int i = 0; i < 12; i++)
        {
            var r = NetworkBatch146150Context.Tls();
            r.Info = "handshake failure";
            r.Destination = i % 2 == 0 ? "198.51.100.147" : "198.51.100.148";
            Assert.False((await rule.EvaluateAsync(NetworkBatch146150Context.At(r, i * 4))).Matched);
        }
    }

    [Fact] public async Task Ordinary_Successful_Sessions_Cannot_Pad_Failure_Count()
    {
        var rule = new R146_TlsHandshakeFailureSpikeRule();
        for(int i=0;i<20;i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch146150Context.At(NetworkBatch146150Context.Tls(),i))).Matched);
    }

    [Fact] public async Task Udp_Contradiction_Is_Rejected()
    {
        var r = NetworkBatch146150Context.Tls();
        r.Info = "handshake failure"; r.IsTcp = false; r.IsUdp = true;
        Assert.False((await new R146_TlsHandshakeFailureSpikeRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Failure_Words_In_Http_Only_Telemetry_Are_Not_Tls()
    {
        var r = NetworkBatch146150Context.Tls();
        r.Info = "handshake failure"; r.Protocol = "HTTP"; r.ApplicationProtocol = "HTTP";
        Assert.False((await new R146_TlsHandshakeFailureSpikeRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Failure_Summary_Is_Bounded()
    {
        var r = NetworkBatch146150Context.Tls();
        r.Info = new string('x', 2048) + " handshake failure";
        Assert.False((await new R146_TlsHandshakeFailureSpikeRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public void Confidence_Threshold_And_Shadow_Mode_Are_Preserved()
    {
        var p = new R146_TlsHandshakeFailureSpikeRule().PrecisionProfile;
        Assert.Equal(12, p.Threshold);
        Assert.Equal(72, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
