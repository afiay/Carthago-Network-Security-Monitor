// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R175AdvancedAccuracyBatchTests
{
    private static TrafficRecord Framed()
    {
        var r=NetworkBatch166175Context.Http("/submit","POST");
        r.HttpRequestHeaders+="\r\nContent-Length: 10\r\nTransfer-Encoding: chunked";
        return r;
    }
    [Fact] public async Task Concrete_ContentLength_TransferEncoding_Conflict_Qualifies()
    {
        Assert.True((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(Framed()))).Matched);
    }
    [Fact] public async Task Single_ContentLength_Is_Benign()
    {
        var r=Framed();r.HttpRequestHeaders="Host: web.internal.local\r\nContent-Length: 10";Assert.False((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Identical_Duplicate_ContentLengths_Are_Not_Conflicting()
    {
        var r=Framed();r.HttpRequestHeaders="Host: web.internal.local\r\nContent-Length: 10\r\nContent-Length: 10";Assert.False((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Different_Duplicate_ContentLengths_Qualify()
    {
        var r=Framed();r.HttpRequestHeaders="Host: web.internal.local\r\nContent-Length: 10\r\nContent-Length: 11";Assert.True((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Info_Only_ClTe_Annotation_Is_Not_Framing()
    {
        var r=Framed();r.HttpRequestHeaders="Host: web.internal.local";r.Info="cl.te chunked";Assert.False((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Http2_Alpn_Contradiction_Is_Suppressed()
    {
        var r=Framed();r.Alpn="h2";Assert.False((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Http_Framing()
    {
        var r=Framed();r.IsTcp=false;r.IsUdp=true;Assert.False((await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Conflicting_Framing_Id_Is_Ignored()
    {
        var r=Framed();var rule=new R175_HttpRequestSmugglingIndicatorRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Request_Target_Secrets_Are_Not_Emitted()
    {
        var r=Framed();r.HttpUri="/submit/SECRET175?token=HIDDEN175";var x=await new R175_HttpRequestSmugglingIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET175",StringComparison.Ordinal)||i.Value.Contains("HIDDEN175",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R175_HttpRequestSmugglingIndicatorRule().PrecisionProfile;
        Assert.Equal(82,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
