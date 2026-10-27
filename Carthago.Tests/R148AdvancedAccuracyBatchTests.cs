// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class R148AdvancedAccuracyBatchTests
{
    [Fact] public async Task Observed_Dynamic_Dns_Sni_On_External_Socket_Matches()
    {
        var r = NetworkBatch146150Context.Tls("remote123.duckdns.org");
        var result = await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r));
        Assert.True(result.Matched); Assert.Equal("R148", Assert.Single(result.Events).RuleId);
    }

    [Fact] public async Task Provider_Apex_Is_Not_Hosted_Subdomain()
    {
        var r = NetworkBatch146150Context.Tls("duckdns.org");
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Provider_Substring_In_Unrelated_Domain_Is_Benign()
    {
        var r = NetworkBatch146150Context.Tls("remote.duckdns.org.example.test");
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Ordinary_Browser_To_Dynamic_Dns_Is_Suppressed()
    {
        var r = NetworkBatch146150Context.Tls("remote123.duckdns.org"); r.ProcessName = "chrome.exe";
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Local_Destination_Socket_Is_Not_Externally_Hosted()
    {
        var r = NetworkBatch146150Context.Tls("remote123.duckdns.org"); r.Destination = "10.148.0.12";
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Http_Host_Without_Observed_Sni_Cannot_Trigger()
    {
        var r = NetworkBatch146150Context.Tls(); r.Sni = null; r.HttpHost = "remote123.duckdns.org";
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public async Task Contradictory_Http_Method_Is_Rejected()
    {
        var r = NetworkBatch146150Context.Tls("remote123.duckdns.org"); r.HttpMethod = "GET";
        Assert.False((await new R148_TlsToDynamicDnsHostRule().EvaluateAsync(NetworkBatch146150Context.At(r))).Matched);
    }

    [Fact] public void Existing_Shadow_And_Floor_Are_Preserved()
    {
        var p = new R148_TlsToDynamicDnsHostRule().PrecisionProfile;
        Assert.Equal(70, p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow, p.DefaultMode);
    }
}
