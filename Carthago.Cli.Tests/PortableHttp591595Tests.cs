// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;
public sealed class PortableHttp591595Tests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path
    };

    private static PacketEvaluationContext At(TrafficRecord record,int seconds=0)
        =>new(record,Sensitivity.Balanced,DateTime.UnixEpoch.AddSeconds(seconds));

    [Theory]
    [InlineData("R591","GET","/ServletApi/../RestApi/LogonCustomization",true)]
    [InlineData("R591","POST","/ServletApi/../RestApi/LogonCustomization",true)]
    [InlineData("R591","GET","/ServletApi/RestApi/LogonCustomization",false)]
    [InlineData("R591","PUT","/ServletApi/../RestApi/LogonCustomization",false)]
    [InlineData("R592","GET","/test.html?dwn=example&fn=sample",true)]
    [InlineData("R592","POST","/test.html?dwn=example&fn=sample",true)]
    [InlineData("R592","GET","/test.html?dwn=example",false)]
    [InlineData("R592","PUT","/test.html?dwn=example&fn=sample",false)]
    [InlineData("R593","GET","/?doAs=`example`",true)]
    [InlineData("R593","POST","/?doAs=`example`",true)]
    [InlineData("R593","GET","/?doAs=example",false)]
    [InlineData("R593","PUT","/?doAs=`example`",false)]
    [InlineData("R594","GET","/rest/api/latest/projects/test?prefix=%00--exec",true)]
    [InlineData("R594","POST","/rest/api/latest/projects/test?prefix=%00--exec",true)]
    [InlineData("R594","GET","/rest/api/latest/projects/test?prefix=example",false)]
    [InlineData("R594","PUT","/rest/api/latest/projects/test?prefix=%00--exec",false)]
    [InlineData("R595","GET","/public/plugins/graph/../../../../example",true)]
    [InlineData("R595","POST","/public/plugins/graph/../../../../example",true)]
    [InlineData("R595","GET","/public/plugins/graph/../../../example",false)]
    [InlineData("R595","PUT","/public/plugins/graph/../../../../example",false)]
    public void ExactRequestPredicates(string id,string method,string path,bool expected)
    {
        var detector=new PortableReplayDispatcher();
        Assert.Equal(expected?WebSignatureObservation.Match:WebSignatureObservation.None,
            detector.Evaluate(id,At(Record(method,path)),out _));
    }

    [Theory]
    [InlineData("R591","/ServletApi/../RestApi/LogonCustomization")]
    [InlineData("R592","/test.html?dwn=example&fn=sample")]
    [InlineData("R593","/?doAs=`example`")]
    [InlineData("R594","/rest/api/latest/projects/test?prefix=%00--exec")]
    [InlineData("R595","/public/plugins/graph/../../../../example")]
    public void EvidenceCooldownAndIsolation(string id,string path)
    {
        var d=new PortableReplayDispatcher();
        var bad=Record("GET",path);bad.Sni="example.test";
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(bad),out _));
        var first=Record("GET",path);
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(first),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(first,1),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(Record("GET",path),-1),out _));
        Assert.Equal(WebSignatureObservation.Suppressed,d.Evaluate(id,At(Record("GET",path),599),out _));
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(Record("GET",path),600),out _));
        Assert.Equal(WebSignatureObservation.Match,new PortableReplayDispatcher().Evaluate(id,At(first),out _));
    }
}
