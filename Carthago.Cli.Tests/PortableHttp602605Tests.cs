// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;
public sealed class PortableHttp602605Tests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=256,L4Len=216,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path
    };

    private static PacketEvaluationContext At(TrafficRecord record,int seconds=0)
        =>new(record,Sensitivity.Balanced,DateTime.UnixEpoch.AddSeconds(seconds));

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
    public void ExactRequestPredicates(string id,string method,string path,bool expected)
    {
        var d=new PortableReplayDispatcher();
        Assert.Equal(expected?WebSignatureObservation.Match:WebSignatureObservation.None,d.Evaluate(id,At(Record(method,path)),out _));
    }

    [Theory]
    [InlineData("R602","GET","/SolarWinds/api/WebResource.axd")]
    [InlineData("R603","GET","/?handle=com.bea.console.handles.JndiBindingHandle&ref=ldap://example.test&server=AdminServer")]
    [InlineData("R604","GET","/ecp/test?__VIEWSTATE=example")]
    [InlineData("R605","POST","/upload.action?filename=../../../../example")]
    public void EvidenceCooldownAndIsolation(string id,string method,string path)
    {
        var d=new PortableReplayDispatcher();
        var bad=Record(method,path);bad.Sni="example.test";
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(bad),out _));
        var first=Record(method,path);
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(first),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(first,1),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(Record(method,path),-1),out _));
        Assert.Equal(WebSignatureObservation.Suppressed,d.Evaluate(id,At(Record(method,path),599),out _));
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(Record(method,path),600),out _));
        Assert.Equal(WebSignatureObservation.Match,new PortableReplayDispatcher().Evaluate(id,At(first),out _));
    }
}
