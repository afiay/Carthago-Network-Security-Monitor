// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableHttp602605ParityTests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=256,L4Len=216,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path
    };

    [Theory]
    [InlineData("R602","GET","/SolarWinds/api/WebResource.axd",true)]
    [InlineData("R602","GET","/SolarWinds/api/css.i18n.ashx",false)]
    [InlineData("R602","POST","/SolarWinds/api/WebResource.axd",true)]
    [InlineData("R602","PUT","/SolarWinds/api/WebResource.axd",false)]
    [InlineData("R603","GET","/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer",true)]
    [InlineData("R603","GET","/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test",false)]
    [InlineData("R603","POST","/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer",false)]
    [InlineData("R603","PUT","/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer",false)]
    [InlineData("R604","GET","/ecp/test?__VIEWSTATE=example",true)]
    [InlineData("R604","GET","/ecp/test?viewstate=example",false)]
    [InlineData("R604","POST","/ecp/test?__VIEWSTATE=example",false)]
    [InlineData("R604","PUT","/ecp/test?__VIEWSTATE=example",false)]
    [InlineData("R605","POST","/upload.action?filename=../../../../example",true)]
    [InlineData("R605","POST","/upload.action?filename=../../../example",false)]
    [InlineData("R605","GET","/upload.action?filename=../../../../example",false)]
    [InlineData("R605","PUT","/upload.action?filename=../../../../example",false)]
    [InlineData("R602","GET","/SolarWinds/api/Orion/Skipi18n/Profiler/example",false)]
    [InlineData("R602","GET","/SolarWinds/api/js.i18n.ashx",false)]
    [InlineData("R604","GET","/owa/test?__VIEWSTATE=example",true)]
    [InlineData("R603","GET","/?handle=com.bea.console.handles.JndiBindingHandle&ref=http://example.test&server=AdminServer",false)]
    public async Task WindowsAndPortableAgree(string id,string method,string path,bool expected)
    {
        var context=new RuleEvaluationContext(Record(method,path),Sensitivity.Balanced,DateTime.UnixEpoch);
        var observation=new PortableReplayDispatcher().Evaluate(id,context.Packet,out _);
        EvidenceDrivenPrecisionRuleBase rule=id switch
        {
            "R602"=>new R602_SolarWindsOrionResourceAuthBypassRequestRule(),
            "R603"=>new R603_WebLogicJndiBindingLdapRequestRule(),
            "R604"=>new R604_ExchangeViewStateQueryRequestRule(),
            "R605"=>new R605_ConfluenceUploadFilenameTraversalRequestRule(),
            _=>throw new ArgumentException(nameof(id))
        };
        var actual=await rule.EvaluateAsync(context);
        Assert.Equal(expected,observation==WebSignatureObservation.Match);
        Assert.Equal(expected,actual.Matched);
        if(expected){var evt=Assert.Single(actual.Events);Assert.Equal(id,evt.RuleId);Assert.Equal(SeverityLevel.High,evt.Severity);}
        else Assert.Empty(actual.Events);
    }
}
