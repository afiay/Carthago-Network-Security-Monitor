// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class PortableR587ParityTests
{
    [Theory]
    [InlineData("GET", "/SetupWizard.aspx/next", true)]
    [InlineData("GET", "/SETUPWIZARD.ASPX/next?q=1", true)]
    [InlineData("GET", "/SetupWizard.aspx", false)]
    [InlineData("POST", "/SetupWizard.aspx/next", false)]
    public async Task WindowsRuleAndPortableObservationAgree(string method,string path,bool expected)
    {
        var r=new TrafficRecord { Source="192.0.2.1",Destination="198.51.100.2",
            SourcePort=51000,DestinationPort=7001,IsTcp=true,Protocol="TCP",
            Length=128,L4Len=88,ApplicationProtocol="HTTP",HttpMethod=method,HttpUri=path };
        var context=new RuleEvaluationContext(r,Sensitivity.Balanced,DateTime.UnixEpoch);
        var observation=new PortableR587Detector().Evaluate(context.Packet,out _);
        var actual=await new R587_ScreenConnectSetupWizardPathRequestRule().EvaluateAsync(context);
        Assert.Equal(expected,observation==WebSignatureObservation.Match);
        Assert.Equal(expected,actual.Matched);
        if(expected)
        {
            var evt=Assert.Single(actual.Events);
            Assert.Equal("R587",evt.RuleId);
            Assert.Equal(SeverityLevel.High,evt.Severity);
        }
        else Assert.Empty(actual.Events);
    }
}
