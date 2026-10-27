// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R172AdvancedAccuracyBatchTests
{
    [Fact] public async Task Explicit_Scanner_And_Browser_Claim_Qualifies()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8 Mozilla/5.0";Assert.True((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Normal_Browser_Claim_Is_Benign()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="Mozilla/5.0 Chrome/124.0";Assert.False((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Explicit_Scanner_Without_Browser_Is_Not_Mismatch()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8";Assert.False((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Incidental_Scanner_Substring_Is_Not_Identity()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="Mozilla/5.0 sqlmapper/1.0";Assert.False((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_UserAgent_Header_Is_Rejected()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8 Mozilla/5.0";r.HttpRequestHeaders+="\r\nUser-Agent: Mozilla/5.0";Assert.False((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Http()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8 Mozilla/5.0";r.IsTcp=false;r.IsUdp=true;Assert.False((await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Packet_Cannot_Raise_Second_Mismatch()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8 Mozilla/5.0";var rule=new R172_ScannerUserAgentWithBrowserClaimMismatchRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task UserAgent_Secret_Is_Not_Persisted()
    {
        var r=NetworkBatch166175Context.Http("/admin");r.HttpUserAgent="sqlmap/1.8 Mozilla/5.0 SECRET172";var x=await new R172_ScannerUserAgentWithBrowserClaimMismatchRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET172",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R172_ScannerUserAgentWithBrowserClaimMismatchRule().PrecisionProfile;
        Assert.Equal(68,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
