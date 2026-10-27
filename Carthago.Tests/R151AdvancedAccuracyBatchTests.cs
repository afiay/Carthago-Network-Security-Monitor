// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R151AdvancedAccuracyBatchTests
{
    [Fact] public async Task Observed_H2_On_Uncommon_Tls_Port_Matches()
    {
        var r = await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(
            NetworkBatch151155Context.At(NetworkBatch151155Context.Tls()));
        Assert.True(r.Matched); Assert.Equal("R151", Assert.Single(r.Events).RuleId);
    }

    [Fact] public async Task Ordinary_Https_Port_Does_Not_Qualify()
    {
        var r = NetworkBatch151155Context.Tls(); r.DestinationPort = 443;
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Http11_Alpn_Is_Not_H2()
    {
        var r = NetworkBatch151155Context.Tls(); r.Alpn = "http/1.1";
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task H2_Words_In_Info_Are_Not_Negotiated_Alpn()
    {
        var r = NetworkBatch151155Context.Tls(); r.Alpn = null; r.Info = "http/2 h2 negotiated";
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Browser_Using_H2_Remains_Benign()
    {
        var r = NetworkBatch151155Context.Tls(); r.ProcessName = "firefox.exe";
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Internal_Destination_Does_Not_Match_External_Rule()
    {
        var r = NetworkBatch151155Context.Tls(); r.Destination = "10.151.0.20";
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public async Task Conflicting_Udp_And_Quic_Transport_Is_Rejected()
    {
        var r = NetworkBatch151155Context.Tls(); r.IsQuic = true;
        Assert.False((await new R151_Http2AlpnOnUncommonPortRule().EvaluateAsync(NetworkBatch151155Context.At(r))).Matched);
    }

    [Fact] public void Floor_And_Shadow_Policy_Remain_Unchanged()
    {
        var p = new R151_Http2AlpnOnUncommonPortRule().PrecisionProfile;
        Assert.Equal(70, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
