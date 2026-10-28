// SPDX-License-Identifier: MIT
using System;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;
namespace Carthago.Tests;
public sealed class R201AdvancedAccuracyBatchTests
{
    private static TrafficRecord K() => NetworkBatch201205Context.Kube();
    private static async Task<bool> Hit(TrafficRecord r) => (await new R201_KubernetesServiceAccountTokenAccessRule().EvaluateAsync(NetworkBatch201205Context.At(r))).Matched;
    [Fact] public async Task Typed_Kubernetes_TokenRequest_Post_Qualifies() => Assert.True(await Hit(K()));
    [Fact] public async Task Get_On_TokenRequest_Path_Is_Not_Token_Issuance_Request()
    {
        var r = K(); r.HttpMethod = "GET"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Port_6443_Alone_Does_Not_Prove_Kubernetes_Api()
    {
        var r = K(); r.HttpHost = "ordinary.example.net"; r.HttpRequestHeaders = "Host: ordinary.example.net";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Mounted_File_Path_Only_In_Packet_Info_Is_Not_Observable_Token_Read()
    {
        var r = K(); r.HttpUri = "/health"; r.Info = "cat /var/run/secrets/kubernetes.io/serviceaccount/token";
        Assert.False(await Hit(r));
    }
    [Fact] public async Task Approved_Kubelet_Process_Remains_Suppressed()
    {
        var r = K(); r.ProcessName = "kubelet.exe"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Http_Authority_Contradiction_Is_Rejected()
    {
        var r = K(); r.HttpRequestHeaders = "Host: other.example.net"; Assert.False(await Hit(r));
    }
    [Fact] public async Task Duplicate_Packet_Id_Does_Not_Produce_Second_Event()
    {
        var rule = new R201_KubernetesServiceAccountTokenAccessRule(); var r = K();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(r))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(r, 1))).Matched);
    }
    [Fact] public async Task Out_Of_Order_Observation_Is_Rejected()
    {
        var rule = new R201_KubernetesServiceAccountTokenAccessRule();
        Assert.True((await rule.EvaluateAsync(NetworkBatch201205Context.At(K(), 10))).Matched);
        Assert.False((await rule.EvaluateAsync(NetworkBatch201205Context.At(K(), 5))).Matched);
    }
    [Fact] public async Task Service_Account_Identifiers_Are_Redacted()
    {
        var x = await new R201_KubernetesServiceAccountTokenAccessRule().EvaluateAsync(NetworkBatch201205Context.At(K()));
        Assert.True(x.Matched);
        Assert.DoesNotContain(Assert.Single(x.Events).StructuredEvidence!.Items, e => e.Value.Contains("serviceaccounts/app", StringComparison.Ordinal));
    }
    [Fact] public void Alert_And_Confidence_Floor_Unchanged()
    {
        var p = new R201_KubernetesServiceAccountTokenAccessRule().PrecisionProfile;
        Assert.Equal(86, p.MinimumConfidence); Assert.Equal(RuleRuntimeMode.Alert, p.DefaultMode);
    }
}
