// SPDX-License-Identifier: MIT
using System.Text.Json;
using Carthago.Cli;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableRuleCapabilityTests
{
    private static async Task<(int Code,string Out,string Error)> Run(params string[] args)
    {
        using var output=new StringWriter();using var error=new StringWriter();
        int code=await CliApplication.RunAsync(args,output,error);
        return(code,output.ToString(),error.ToString());
    }

    [Fact]
    public async Task CatalogListsOnlyExecutablePortableRulesInOrder()
    {
        var result=await Run("rules","capabilities","--json");
        Assert.Equal(0,result.Code);Assert.Empty(result.Error);
        using var json=JsonDocument.Parse(result.Out);var root=json.RootElement;
        Assert.Equal("compiled_portable_catalog",root.GetProperty("scope").GetString());
        Assert.Equal("not_assessed",root.GetProperty("registration").GetString());
        Assert.Equal(19,root.GetProperty("supportedCount").GetInt32());
        var rows=root.GetProperty("rules").EnumerateArray().ToArray();
        Assert.Equal(new[]{"R586","R587","R588","R589","R590","R591","R592","R593","R594","R595","R596","R597","R598","R599","R600","R602","R603","R604","R605"},rows.Select(r=>r.GetProperty("ruleId").GetString()).ToArray());
        foreach(var r in rows)
        {
            Assert.Equal("supported",r.GetProperty("status").GetString());
            Assert.Equal("not_assessed",r.GetProperty("qualification").GetString());
            Assert.Equal("not_evaluated_by_replay",r.GetProperty("windowsRuntimePolicy").GetString());
            Assert.Equal(600,r.GetProperty("cooldownSeconds").GetInt32());
            Assert.Equal(new[]{"pcap","pcapng"},r.GetProperty("executionEnvironments").EnumerateArray().Select(x=>x.GetString()).ToArray());
            Assert.Contains("http.uri",r.GetProperty("requiredEvidence").EnumerateArray().Select(x=>x.GetString()));
            if(r.GetProperty("ruleId").GetString()=="R596")Assert.Contains("http.user_agent",r.GetProperty("requiredEvidence").EnumerateArray().Select(x=>x.GetString()));
            if(r.GetProperty("ruleId").GetString()=="R600")Assert.Equal("POST",Assert.Single(r.GetProperty("httpMethods").EnumerateArray()).GetString());
        }
        var portable=await Run("rules","capabilities","--portable","--json");
        Assert.Equal(result.Out,portable.Out);
    }

    [Fact]
    public async Task SupportedLookupReportsActualMethodsAndUnsupportedDoesNotClaimRegistration()
    {
        var supported=await Run("rules","capabilities","R590","--json");
        using var a=JsonDocument.Parse(supported.Out);var r=a.RootElement.GetProperty("rules")[0];
        Assert.Equal(0,supported.Code);
        Assert.Equal("GET",Assert.Single(r.GetProperty("httpMethods").EnumerateArray()).GetString());
        var unsupported=await Run("rules","capabilities","R1000","--json");
        Assert.Equal(0,unsupported.Code);
        using var b=JsonDocument.Parse(unsupported.Out);r=b.RootElement.GetProperty("rules")[0];
        Assert.Equal("unsupported_detector",r.GetProperty("status").GetString());
        Assert.Equal("no_portable_detector_registered",r.GetProperty("reason").GetString());
        Assert.Equal("not_assessed",r.GetProperty("registration").GetString());
        Assert.Empty(r.GetProperty("executionEnvironments").EnumerateArray());
    }

    [Theory]
    [InlineData("r589")]
    [InlineData("R0589")]
    [InlineData("R589 ")]
    [InlineData("--live")]
    public async Task InvalidLookupFailsUsage(string id)
    {
        var result=await Run("rules","capabilities",id,"--json");
        Assert.Equal(2,result.Code);Assert.Empty(result.Out);
    }

    [Fact]
    public async Task ExtraArgumentsRejected()
    {
        var result=await Run("rules","capabilities","--portable","R589","--json");
        Assert.Equal(2,result.Code);Assert.Empty(result.Out);
    }

    [Fact]
    public void CatalogFactoriesAndDispatcherAgreeAndOwnIndependentState()
    {
        var paths=new Dictionary<string,string>{
            ["R586"]="/wp-content/plugins/wp2shell_test/file.php",
            ["R587"]="/SetupWizard.aspx/next",
            ["R588"]="/LogoImageHandler.ashx?clazz=example",
            ["R589"]="/config/keystore/test.jsp",
            ["R590"]="/?search=%00{.cmd.exe",
            ["R591"]="/ServletApi/../RestApi/LogonCustomization",
            ["R592"]="/test.html?dwn=example&fn=sample",
            ["R593"]="/?doAs=`example`",
            ["R594"]="/rest/api/latest/projects/test?prefix=%00--exec",
            ["R595"]="/public/plugins/graph/../../../../example",
            ["R596"]="/cgi-bin/jarrewrite.sh",
            ["R597"]="/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00",
            ["R598"]="/?file=C:/Users/example",
            ["R599"]="/apply_abstract.cgi?file=..%2fexample",
            ["R600"]="/owa/auth/Current/themes/resources/example",
            ["R602"]="/SolarWinds/api/WebResource.axd",
            ["R603"]="/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer",
            ["R604"]="/ecp/test?__VIEWSTATE=example",
            ["R605"]="/upload.action?filename=../../../../example"};
        var first=new PortableReplayDispatcher();var second=new PortableReplayDispatcher();
        Assert.Equal(paths.Keys.OrderBy(x=>x).ToArray(),PortableRuleCatalog.All.Select(x=>x.RuleId).ToArray());
        foreach(var capability in PortableRuleCatalog.All)
        {
            var id=capability.RuleId;
            Assert.True(PortableReplayDispatcher.Supports(id));
            var record=new TrafficRecord{Source="192.0.2.1",Destination="198.51.100.2",
                SourcePort=51000,DestinationPort=7001,Protocol="TCP",IsTcp=true,Length=128,L4Len=88,
                ApplicationProtocol="HTTP",HttpMethod=id is "R600" or "R605"?"POST":"GET",HttpUri=paths[id],HttpUserAgent=id=="R596"?"() { example":null};
            var context=new PacketEvaluationContext(record,Sensitivity.Balanced,DateTime.UnixEpoch);
            Assert.Equal(WebSignatureObservation.Match,first.Evaluate(id,context,out _));
            Assert.Equal(WebSignatureObservation.None,first.Evaluate(id,context,out _));
            Assert.Equal(WebSignatureObservation.Match,second.Evaluate(id,context,out _));
        }
        Assert.False(PortableReplayDispatcher.Supports("R1000"));
        Assert.Throws<ArgumentException>(()=>first.Evaluate("R1000",null!,out _));
    }

    [Fact]
    public async Task TextCatalogAndCancellationRemainExplicit()
    {
        var result=await Run("rules","capabilities","R1000");
        Assert.Equal(0,result.Code);Assert.Contains("unsupported_detector",result.Out);
        Assert.Contains("not assessed",result.Out);
        using var cancel=new CancellationTokenSource();cancel.Cancel();
        using var output=new StringWriter();using var error=new StringWriter();
        Assert.Equal(130,await CliApplication.RunAsync(new[]{"rules","capabilities","--json"},output,error,cancel.Token));
        Assert.Empty(output.ToString());
    }

    [Fact]
    public async Task HeaderAbsenceRuleRemainsUnsupportedWithExplicitReason()
    {
        var result=await Run("rules","capabilities","R601","--json");
        Assert.Equal(0,result.Code);
        using var json=JsonDocument.Parse(result.Out);
        var row=json.RootElement.GetProperty("rules")[0];
        Assert.Equal("unsupported_detector",row.GetProperty("status").GetString());
        Assert.Equal("complete_http_header_evidence_required",row.GetProperty("reason").GetString());
        Assert.False(PortableReplayDispatcher.Supports("R601"));
    }
}
