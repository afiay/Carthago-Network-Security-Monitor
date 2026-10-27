// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R152AdvancedAccuracyBatchTests
{
    [Fact] public async Task Five_Distinct_Asns_From_One_Client_Reach_Threshold()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        RuleEvaluationResult? last = null;
        for(int i=0;i<5;i++)
        {
            var r = NetworkBatch151155Context.Tls(); r.WhoisASN = $"AS{100+i}";
            last = await rule.EvaluateAsync(NetworkBatch151155Context.At(r, i*10));
        }
        Assert.True(last!.Matched); Assert.Equal("R152", Assert.Single(last.Events).RuleId);
    }

    [Fact] public async Task Repeated_Same_Asn_Is_Not_Fanout()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        for(int i=0;i<6;i++)
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(NetworkBatch151155Context.Tls(),i*10))).Matched);
    }

    [Fact] public async Task Duplicate_Packet_Identifier_Does_Not_Inflate_Fanout()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        var id = NetworkBatch151155Context.Tls().Id;
        for(int i=0;i<6;i++)
        {
            var r = NetworkBatch151155Context.Tls(); r.Id = id; r.WhoisASN = $"AS{100+i}";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Different_Source_Clients_Do_Not_Combine_ASNs()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        for(int i=0;i<4;i++)
        {
            var r = NetworkBatch151155Context.Tls(); r.WhoisASN = $"AS{100+i}";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
        var other = NetworkBatch151155Context.Tls();
        other.Source = "10.151.0.11"; other.WhoisASN = "AS104";
        Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(other,50))).Matched);
    }

    [Fact] public async Task Placeholder_Or_Malformed_Asn_Does_Not_Qualify()
    {
        var r = NetworkBatch151155Context.Tls(); r.WhoisASN = "unknown ASN";
        Assert.False((await new R152_TlsFingerprintFanOutToManyAsnsRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Browser_Asn_Fanout_Is_Not_Alertable()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        for(int i=0;i<5;i++)
        {
            var r = NetworkBatch151155Context.Tls(); r.WhoisASN = $"AS{200+i}"; r.ProcessName = "chrome.exe";
            Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r,i*10))).Matched);
        }
    }

    [Fact] public async Task Internal_Socket_And_Udp_Do_Not_Qualify()
    {
        var rule = new R152_TlsFingerprintFanOutToManyAsnsRule();
        var r = NetworkBatch151155Context.Tls(); r.Destination = "10.151.0.21";
        Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
        var udp = NetworkBatch151155Context.Tls(); udp.IsUdp = true; udp.IsTcp = false;
        Assert.False((await rule.EvaluateAsync(NetworkBatch151155Context.At(udp,10))).Matched);
    }

    [Fact] public void Existing_Candidate_Shadow_Floor_And_Threshold_Are_Preserved()
    {
        var p = new R152_TlsFingerprintFanOutToManyAsnsRule().PrecisionProfile;
        Assert.Equal(5, p.Threshold);
        Assert.Equal(74, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
