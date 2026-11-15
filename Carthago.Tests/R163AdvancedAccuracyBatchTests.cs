// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R163AdvancedAccuracyBatchTests
{

    private static TrafficRecord Metadata()
    {
        var r=NetworkBatch156165Context.Http("/latest/meta-data/iam/security-credentials/role");
        r.Source="10.156.0.11";r.Destination="169.254.169.254";r.DestinationPort=80;
        r.HttpHost="169.254.169.254";r.HttpRequestHeaders="Host: 169.254.169.254";
        r.Protocol="HTTP";r.ApplicationProtocol="HTTP";r.ApplicationService="HTTP";
        r.ProcessName="custom-app.exe";return r;
    }
    [Fact] public async Task Attributed_Credential_Path_Remains_Observable()
    {
        Assert.True((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(Metadata()))).Matched);
    }
    [Fact] public async Task Known_Guest_Agent_Is_Suppressed()
    {
        var r=Metadata();r.ProcessName="amazon-ssm-agent";
        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Forged_Host_Without_Metadata_Socket_Is_Not_Credential_Proof()
    {
        var r=Metadata();r.Destination="10.156.0.20";
        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Ordinary_Instance_Metadata_Path_Is_Not_Credential_Access()
    {
        var r=Metadata();r.HttpUri="/latest/meta-data/instance-id";
        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Contradiction_Is_Not_Http_Metadata()
    {
        var r=Metadata();r.IsUdp=true;r.IsTcp=false;
        Assert.False((await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Replayed_Record_Does_Not_Realert()
    {
        var rule=new R163_SsrfMetadataServiceProbeRule();var r=Metadata();
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,3))).Matched);
    }
    [Fact] public async Task Credential_Path_Is_Redacted_From_New_Structured_Evidence()
    {
        var r=Metadata();r.HttpUri+="/SECRETROLE";
        var result=await new R163_SsrfMetadataServiceProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        Assert.DoesNotContain(Assert.Single(result.Events).StructuredEvidence!.Items,x=>x.Value.Contains("SECRETROLE",StringComparison.Ordinal));
    }
    [Theory]
    [InlineData("traceparent: 00-0123456789abcdef0123456789abcdef-0123456789abcdef-01")]
    [InlineData("X-Request-Id: synthetic-request-123")]
    public async Task Caller_Supplied_Trace_Headers_Do_Not_Establish_Causality(string header)
    {
        var r = Metadata();
        r.HttpRequestHeaders += "\r\n" + header;
        var result = await new R163_SsrfMetadataServiceProbeRule()
            .EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        var items = Assert.Single(result.Events).StructuredEvidence!.Items;
        Assert.Contains(items, x => x.Value == "not-established");
        Assert.Contains(items, x => x.Value == "not-observed");
        Assert.DoesNotContain(items, x => x.Value.Contains(header, StringComparison.Ordinal));
    }
    [Theory]
    [InlineData("local-tcp-socket")]
    [InlineData("etw")]
    public async Task Process_Attribution_Alone_Does_Not_Establish_Request_Ancestry(string attribution)
    {
        var r = Metadata();
        r.ProcessId = 4242;
        r.ProcessAttribution = attribution;
        var result = await new R163_SsrfMetadataServiceProbeRule()
            .EvaluateAsync(NetworkBatch156165Context.At(r));
        Assert.True(result.Matched);
        var items = Assert.Single(result.Events).StructuredEvidence!.Items;
        Assert.Contains(items, x => x.Value == "not-established");
        Assert.Contains(items, x => x.Value == "not-observed");
    }
    [Fact] public void Policy_And_Confidence_Floor_Are_Preserved()
    {
        var p=new R163_SsrfMetadataServiceProbeRule().PrecisionProfile;
        Assert.Equal(84,p.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,p.DefaultMode);
    }
}
