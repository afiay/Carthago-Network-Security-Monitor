// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R171AdvancedAccuracyBatchTests
{
    [Fact] public async Task Explicit_ExecuteCommand_Soap_Action_Is_Observable()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders+="\r\nSOAPAction: \"executeCommand\"";Assert.True((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Ordinary_Business_Soap_Action_Is_Benign()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders+="\r\nSOAPAction: \"GetWeather\"";Assert.False((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Suspicious_Substring_Inside_Help_Action_Is_Not_Exploit()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders+="\r\nSOAPAction: \"ExecuteCommandHelp\"";Assert.False((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Missing_Xml_Content_Type_Does_Not_Qualify()
    {
        var r=NetworkBatch166175Context.Http("/service.asmx","POST");r.HttpRequestHeaders+="\r\nSOAPAction: \"executeCommand\"";Assert.False((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Cannot_Prove_Soap()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders+="\r\nSOAPAction: \"executeCommand\"";r.IsTcp=false;r.IsUdp=true;Assert.False((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Conflicting_Host_Header_Is_Rejected()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders="Host: wrong.example\r\nContent-Type: text/xml\r\nSOAPAction: executeCommand";Assert.False((await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);
    }
    [Fact] public async Task Duplicate_Record_Id_Does_Not_Realert()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx");r.HttpRequestHeaders+="\r\nSOAPAction: executeCommand";var rule=new R171_SoapActionExploitPatternRule();Assert.True((await rule.EvaluateAsync(NetworkBatch166175Context.At(r))).Matched);Assert.False((await rule.EvaluateAsync(NetworkBatch166175Context.At(r,2))).Matched);
    }
    [Fact] public async Task Soap_Action_And_Query_Secrets_Are_Not_Emitted()
    {
        var r=NetworkBatch166175Context.Xml("/service.asmx?token=SECRET171");r.HttpRequestHeaders+="\r\nSOAPAction: urn:SECRET171/executeCommand";var x=await new R171_SoapActionExploitPatternRule().EvaluateAsync(NetworkBatch166175Context.At(r));Assert.True(x.Matched);Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items,i=>i.Value.Contains("SECRET171",StringComparison.Ordinal));
    }
    [Fact] public void Runtime_Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R171_SoapActionExploitPatternRule().PrecisionProfile;
        Assert.Equal(74,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Shadow,p.DefaultMode);
    }
}
