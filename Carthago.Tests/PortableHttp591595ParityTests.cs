// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;
public sealed class PortableHttp591595ParityTests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Id=Guid.NewGuid(),Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path
    };

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
    public async Task WindowsAndPortableAgree(string id,string method,string path,bool expected)
    {
        var context=new RuleEvaluationContext(Record(method,path),Sensitivity.Balanced,DateTime.UnixEpoch);
        var observation=new PortableReplayDispatcher().Evaluate(id,context.Packet,out _);
        EvidenceDrivenPrecisionRuleBase rule=id switch
        {
            "R591"=>new R591_AdSelfServiceSuspiciousEndpointRequestRule(),
            "R592"=>new R592_DewmodeWebshellQueryRequestRule(),
            "R593"=>new R593_ApacheSparkDoAsBacktickRequestRule(),
            "R594"=>new R594_BitbucketArchiveExecPrefixRequestRule(),
            "R595"=>new R595_GrafanaPluginTraversalRequestRule(),
            _=>throw new ArgumentException(nameof(id))
        };
        var actual=await rule.EvaluateAsync(context);
        Assert.Equal(expected,observation==WebSignatureObservation.Match);
        Assert.Equal(expected,actual.Matched);
        if(expected){var evt=Assert.Single(actual.Events);Assert.Equal(id,evt.RuleId);Assert.Equal(SeverityLevel.High,evt.Severity);}
        else Assert.Empty(actual.Events);
    }
}
