// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableHttp596600ParityTests
{
    private static TrafficRecord Record(string method,string path,string? ua)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path,HttpUserAgent=ua
    };

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
    public async Task WindowsAndPortableAgree(string id,string method,string path,string? ua,bool expected)
    {
        var context=new RuleEvaluationContext(Record(method,path,ua),Sensitivity.Balanced,DateTime.UnixEpoch);
        var observation=new PortableReplayDispatcher().Evaluate(id,context.Packet,out _);
        EvidenceDrivenPrecisionRuleBase rule=id switch
        {
            "R596"=>new R596_SonicWallJarrewriteAbuseRequestRule(),
            "R597"=>new R597_ModxTvsClassKeyTraversalRequestRule(),
            "R598"=>new R598_WindowsLocalPathInHttpQueryRule(),
            "R599"=>new R599_ArcadyanAbstractConfigTraversalRequestRule(),
            "R600"=>new R600_ExchangeHafniumThemesResourcePostRequestRule(),
            _=>throw new ArgumentException(nameof(id))
        };
        var actual=await rule.EvaluateAsync(context);
        Assert.Equal(expected,observation==WebSignatureObservation.Match);
        Assert.Equal(expected,actual.Matched);
        if(expected){var evt=Assert.Single(actual.Events);Assert.Equal(id,evt.RuleId);Assert.Equal(SeverityLevel.High,evt.Severity);}
        else Assert.Empty(actual.Events);
    }
}
