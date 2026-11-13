// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableR587Tests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",
        HttpMethod=method,HttpUri=path
    };
    private static PacketEvaluationContext At(TrafficRecord record,int seconds=0)
        =>new(record,Sensitivity.Balanced,DateTime.UnixEpoch.AddSeconds(seconds));

    [Theory]
    [InlineData("GET","/SetupWizard.aspx/next",true)]
    [InlineData("GET","/SETUPWIZARD.ASPX/next?q=1",true)]
    [InlineData("GET","/SetupWizard.aspx",false)]
    [InlineData("GET","/other?q=/SetupWizard.aspx/next",false)]
    [InlineData("POST","/SetupWizard.aspx/next",false)]
    [InlineData("PUT","/SetupWizard.aspx/next",false)]
    public void PreservesExistingSignature(string method,string path,bool expected)
    {
        Assert.Equal(expected?WebSignatureObservation.Match:WebSignatureObservation.None,
            new PortableR587Detector().Evaluate(At(Record(method,path)),out _));
    }

    [Fact]
    public void ContradictoryEvidenceAndCooldown()
    {
        var detector=new PortableR587Detector();
        var bad=Record("GET","/SetupWizard.aspx/next");bad.Sni="example.test";
        Assert.Equal(WebSignatureObservation.None,detector.Evaluate(At(bad),out _));
        var first=Record("GET","/SetupWizard.aspx/next");var second=Record("GET","/SetupWizard.aspx/next");
        Assert.Equal(WebSignatureObservation.Match,detector.Evaluate(At(first),out _));
        Assert.Equal(WebSignatureObservation.None,detector.Evaluate(At(first,1),out _));
        Assert.Equal(WebSignatureObservation.None,detector.Evaluate(At(second,-1),out _));
        Assert.Equal(WebSignatureObservation.Suppressed,detector.Evaluate(At(second,599),out _));
        Assert.Equal(WebSignatureObservation.Match,detector.Evaluate(At(second,600),out _));
    }
}
