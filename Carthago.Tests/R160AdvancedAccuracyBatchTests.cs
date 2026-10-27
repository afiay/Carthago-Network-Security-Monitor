// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R160AdvancedAccuracyBatchTests
{

    [Fact] public async Task Kubernetes_Secrets_On_6443_Matches()
    {
        var r=NetworkBatch156165Context.Http("/api/v1/secrets");r.DestinationPort=6443;
        Assert.True((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Kubernetes_Namespace_On_Cluster_Host_Matches()
    {
        var r=NetworkBatch156165Context.Http("/api/v1/namespaces");r.HttpHost="kubernetes.internal.local";r.HttpRequestHeaders="Host: kubernetes.internal.local";
        Assert.True((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Generic_Https_Api_443_Is_Not_Cluster_Proof()
    {
        Assert.False((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(NetworkBatch156165Context.Http("/api/v1/secrets")))).Matched);
    }
    [Fact] public async Task Kubernetes_Lookalike_Path_Is_Rejected()
    {
        var r=NetworkBatch156165Context.Http("/api/v1/secretsdump");r.DestinationPort=6443;
        Assert.False((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Contradictory_Host_And_Uri_Are_Rejected()
    {
        var r=NetworkBatch156165Context.Http("https://other.example.test/api/v1/secrets");r.DestinationPort=6443;
        Assert.False((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Udp_Metadata_Is_Not_Http()
    {
        var r=NetworkBatch156165Context.Http("/api/v1/secrets");r.DestinationPort=6443;r.IsTcp=false;r.IsUdp=true;
        Assert.False((await new R160_KubernetesApiProbeRule().EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
    }
    [Fact] public async Task Repeated_Packet_Id_Cannot_Realert()
    {
        var rule=new R160_KubernetesApiProbeRule();var r=NetworkBatch156165Context.Http("/api/v1/secrets");r.DestinationPort=6443;
        Assert.True((await rule.EvaluateAsync(NetworkBatch156165Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch156165Context.At(r,5))).Matched);
    }
    [Fact] public void Configured_Mode_And_Confidence_Floor_Remain_Unchanged()
    {
        var profile=new R160_KubernetesApiProbeRule().PrecisionProfile;
        Assert.Equal(78,profile.MinimumConfidence);
        Assert.Equal(RuleRuntimeMode.Alert,profile.DefaultMode);
    }
}
