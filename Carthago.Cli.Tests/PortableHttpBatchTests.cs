// SPDX-License-Identifier: MIT
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Cli.Tests;

public sealed class PortableHttpBatchTests
{
    private static TrafficRecord Record(string method,string path)=>new()
    {
        Source="192.0.2.1",Destination="198.51.100.2",SourcePort=51000,DestinationPort=7001,
        Protocol="TCP",IsTcp=true,Length=128,L4Len=88,ApplicationProtocol="HTTP",
        HttpMethod=method,HttpUri=path
    };

    private static PacketEvaluationContext At(TrafficRecord r,int seconds=0)
        =>new(r,Sensitivity.Balanced,DateTime.UnixEpoch.AddSeconds(seconds));

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
    public void PreservesOriginalSignature(string id,string method,string path,bool expected)
    {
        var d=new PortableReplayDispatcher();
        Assert.Equal(expected?WebSignatureObservation.Match:WebSignatureObservation.None,
            d.Evaluate(id,At(Record(method,path)),out _));
    }

    [Theory]
    [InlineData("R586","/wp-content/plugins/wp2shell_test/file.php")]
    [InlineData("R588","/LogoImageHandler.ashx?clazz=example")]
    [InlineData("R590","/?search=%00{.cmd.exe")]
    public void EvidenceAndCooldownRemainIndependent(string id,string path)
    {
        var d=new PortableReplayDispatcher();
        var bad=Record("GET",path);bad.Sni="example.test";
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(bad),out _));
        var first=Record("GET",path);var second=Record("GET",path);
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(first),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(first,1),out _));
        Assert.Equal(WebSignatureObservation.None,d.Evaluate(id,At(second,-1),out _));
        Assert.Equal(WebSignatureObservation.Suppressed,d.Evaluate(id,At(second,599),out _));
        Assert.Equal(WebSignatureObservation.Match,d.Evaluate(id,At(second,600),out _));
        Assert.Equal(WebSignatureObservation.Match,new PortableReplayDispatcher().Evaluate(id,At(first),out _));
    }
}
