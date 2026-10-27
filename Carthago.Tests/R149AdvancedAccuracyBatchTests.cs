// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R149AdvancedAccuracyBatchTests
{
    [Fact] public async Task Explicit_Ip_Literal_Sni_Matches()
    {
        var r = NetworkBatch146150Context.Tls("203.0.113.77");
        var result = await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r));
        Assert.True(result.Matched); Assert.Equal("R149", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Normal_Hostname_Sni_Does_Not_Match()
    {
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(
            NetworkBatch146150Context.At(NetworkBatch146150Context.Tls()))).Matched);
    }

    [Fact] public async Task Absent_Sni_Cannot_Use_Destination_IP_As_Substitute()
    {
        var r = NetworkBatch146150Context.Tls(); r.Sni = null;
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Header_Host_Ip_Is_Not_Observed_Sni()
    {
        var r = NetworkBatch146150Context.Tls(); r.Sni = null; r.HttpHost = "203.0.113.77";
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Udp_Telemetry_Does_Not_Qualify()
    {
        var r = NetworkBatch146150Context.Tls("203.0.113.77");
        r.IsTcp = false; r.IsUdp = true;
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Contradictory_Http_Method_Is_Rejected()
    {
        var r = NetworkBatch146150Context.Tls("203.0.113.77"); r.HttpMethod = "GET";
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Info_Only_Ip_Sni_Words_Do_Not_Qualify()
    {
        var r = NetworkBatch146150Context.Tls(); r.Sni = null; r.Info = "SNI 203.0.113.77";
        Assert.False((await new R149_IpLiteralUsedAsTlsNameRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public void Floor_And_Default_Shadow_Are_Preserved()
    {
        var p = new R149_IpLiteralUsedAsTlsNameRule().PrecisionProfile;
        Assert.Equal(70, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
