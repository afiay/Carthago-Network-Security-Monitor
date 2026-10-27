// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R170AdvancedAccuracyBatchTests
{
    [Fact] public async Task Observable_Query_Encoded_Xml_Entity_Qualifies()
    {
        Assert.True((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Xml(NetworkBatch166175Context.XxePath())))).Matched);
    }
    [Fact] public async Task Ordinary_Xml_Without_Entity_Is_Benign()
    {
        Assert.False((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(NetworkBatch166175Context.Xml("/soap/order?xml=%3COrder%3E1%3C/Order%3E")))).Matched);
    }
    [Fact] public async Task Info_Only_Claim_Does_Not_Prove_Xml_Body()
    {
        var r=NetworkBatch166175Context.Xml();r.Info="<!DOCTYPE foo [<!ENTITY xxe SYSTEM file:///etc/passwd>]";Assert.False((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Doctype_Without_External_Entity_Is_Not_XXE()
    {
        var r=NetworkBatch166175Context.Xml("/soap/order?xml=%3C!DOCTYPE%20note%3E");Assert.False((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Xml_Content_Type_Is_Rejected()
    {
        var r=NetworkBatch166175Context.Xml(NetworkBatch166175Context.XxePath());r.HttpRequestHeaders="Host: web.internal.local";Assert.False((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Http_Xml()
    {
        var r=NetworkBatch166175Context.Xml(NetworkBatch166175Context.XxePath());r.IsTcp=false;r.IsUdp=true;Assert.False((await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Xml_Query_Id_Does_Not_Realert()
    {
        var rule=new R170_XxePayloadIndicatorRule();var r=NetworkBatch166175Context.Xml(NetworkBatch166175Context.XxePath());Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Encoded_Query_And_Secret_Are_Not_Emitted()
    {
        var r=NetworkBatch166175Context.Xml(NetworkBatch166175Context.XxePath()+"&token=SECRET170");var x=await new R170_XxePayloadIndicatorRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET170",StringComparison.Ordinal)||i.Value.Contains("/etc/passwd",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R170_XxePayloadIndicatorRule().PrecisionProfile;
        Assert.Equal(80,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
