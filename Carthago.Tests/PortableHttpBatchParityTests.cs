// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class PortableHttpBatchParityTests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",
        HttpMethod=method,HttpUri=path
    };

    [Theory]
    [InlineData("R586","GET","/wp-content/plugins/wp2shell_test/file.php",true)]
    [InlineData("R586","POST","/WP-CONTENT/PLUGINS/WP2SHELL_test/file.php",true)]
    [InlineData("R586","GET","/wp-content/plugins/wp2shell/file.php",false)]
    [InlineData("R586","GET","/other?x=/wp-content/plugins/wp2shell_test/file.php",false)]
    [InlineData("R586","PUT","/wp-content/plugins/wp2shell_test/file.php",false)]
    [InlineData("R588","GET","/LogoImageHandler.ashx?clazz=example",true)]
    [InlineData("R588","POST","/LOGOIMAGEHANDLER.ASHX?CLAZZ=example",true)]
    [InlineData("R588","GET","/LogoImageHandler.ashx?class=example",false)]
    [InlineData("R588","GET","/other?clazz=example",false)]
    [InlineData("R588","PUT","/LogoImageHandler.ashx?clazz=example",false)]
    [InlineData("R590","GET","/?search=%00{.cmd.exe",true)]
    [InlineData("R590","GET","/?search=%00{.powershell",true)]
    [InlineData("R590","GET","/?search=%00{.example",false)]
    [InlineData("R590","GET","/?search=cmd.exe",false)]
    [InlineData("R590","POST","/?search=%00{.cmd.exe",false)]
    public async Task WindowsAndPortableAgree(string id,string method,string path,bool expected)
    {
        var record=Record(method,path);
        var context=new RuleEvaluationContext(record,Sensitivity.Balanced,DateTime.UnixEpoch);
        var observation=new PortableReplayDispatcher().Evaluate(id,context.Packet,out _);
        EvidenceDrivenPrecisionRuleBase rule=id switch
        {
            "R586"=>new R586_Wp2ShellPluginAccessRequestRule(),
            "R588"=>new R588_SolarWindsSupernovaHandlerRequestRule(),
            "R590"=>new R590_RejettoHfsSearchPayloadRequestRule(),
            _=>throw new ArgumentException(nameof(id))
        };
        var actual=await rule.EvaluateAsync(context);
        Assert.Equal(expected,observation==WebSignatureObservation.Match);
        Assert.Equal(expected,actual.Matched);
        if(expected)
        {
            var evt=Assert.Single(actual.Events);
            Assert.Equal(id,evt.RuleId);
            Assert.Equal(SeverityLevel.High,evt.Severity);
        }
        else Assert.Empty(actual.Events);
    }
}
