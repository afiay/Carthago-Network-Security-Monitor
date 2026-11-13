// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;
public sealed class PortableHttp596600Tests
{
    private static TrafficRecord Record(string method,string path,string? ua)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path,HttpUserAgent=ua
    };

    private static PacketEvaluationContext At(TrafficRecord record,int seconds=0)
        =>new(record,Sensitivity.Balanced,DateTime.UnixEpoch.AddSeconds(seconds));

    [Theory]
    [InlineData("R596","GET","/cgi-bin/jarrewrite.sh","() { example",true)]
    [InlineData("R596","POST","/cgi-bin/jarrewrite.sh","() { example",true)]
    [InlineData("R596","GET","/cgi-bin/other.sh","() { example",false)]
    [InlineData("R596","PUT","/cgi-bin/jarrewrite.sh","() { example",false)]
    [InlineData("R597","GET","/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00",null,true)]
    [InlineData("R597","POST","/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00",null,true)]
    [InlineData("R597","GET","/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini",null,false)]
    [InlineData("R597","PUT","/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00",null,false)]
    [InlineData("R598","GET","/?file=C:/Users/example",null,true)]
    [InlineData("R598","POST","/?file=C:/Users/example",null,true)]
    [InlineData("R598","GET","/?file=D:/Users/example",null,false)]
    [InlineData("R598","PUT","/?file=C:/Users/example",null,false)]
    [InlineData("R599","GET","/apply_abstract.cgi?file=..%2fexample",null,true)]
    [InlineData("R599","POST","/apply_abstract.cgi?file=..%2fexample",null,true)]
    [InlineData("R599","GET","/images/apply_abstract.cgi?file=..%2fexample",null,false)]
    [InlineData("R599","PUT","/apply_abstract.cgi?file=..%2fexample",null,false)]
    [InlineData("R600","GET","/owa/auth/Current/themes/resources/example",null,false)]
    [InlineData("R600","POST","/owa/auth/Current/themes/resources/example",null,true)]
    [InlineData("R600","POST","/owa/auth/Current/themes/other/example",null,false)]
    [InlineData("R600","PUT","/owa/auth/Current/themes/resources/example",null,false)]
    [InlineData("R596","GET","/cgi-bin/jarrewrite.sh",null,false)]
    [InlineData("R596","GET","/cgi-bin/jarrewrite.sh","Mozilla",false)]
    [InlineData("R598","GET","/?file=C%3A%5CWindows",null,true)]
    [InlineData("R599","GET","/css/apply_abstract.cgi?file=..%2fexample",null,false)]
    public void ExactRequestPredicates(string id,string method,string path,string? ua,bool expected)
    {
        var d=new PortableReplayDispatcher();
        Assert.Equal(expected?WebSignatureObservation.Match:WebSignatureObservation.None,d.Evaluate(id,At(Record(method,path,ua)),out _));
    }

    [Theory]
    [InlineData("R596","GET","/cgi-bin/jarrewrite.sh","() { example")]
    [InlineData("R597","GET","/manager/controllers/default/resource/tvs.php?class_key=../windows/win.ini%00",null)]
    [InlineData("R598","GET","/?file=C:/Users/example",null)]
    [InlineData("R599","GET","/apply_abstract.cgi?file=..%2fexample",null)]
    [InlineData("R600","POST","/owa/auth/Current/themes/resources/example",null)]
    public void EvidenceCooldownAndIsolation(string id,string method,string path,string? ua)
    {
        var d=new PortableReplayDispatcher();
        var bad=Record(method,path,ua);bad.Sni="example.test";
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(bad),out _));
        var first=Record(method,path,ua);
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(first),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(first,1),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(Record(method,path,ua),-1),out _));
        Assert.Equal(WebSignatureObservation.Suppressed,d.Evaluate(id,At(Record(method,path,ua),599),out _));
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(Record(method,path,ua),600),out _));
        Assert.Equal(WebSignatureObservation.Match,new PortableReplayDispatcher().Evaluate(id,At(first),out _));
    }
}
