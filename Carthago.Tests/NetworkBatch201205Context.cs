// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch201205Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 3, 30, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Http(string path, string method = "GET", string host = "registry.external.example")
    {
        var r = NetworkBatch166175Context.Http(path, method);
        r.Id = Guid.NewGuid(); r.Source = "10.201.0.10"; r.Destination = "9.9.9.9";
        r.HttpHost = host; r.HttpRequestHeaders = "Host: " + host;
        r.ProcessName = "curl.exe"; r.Length = 400_000; r.L4Len = 400_000;
        return r;
    }
    internal static TrafficRecord Kube()
    {
        var r = Http("/api/v1/namespaces/default/serviceaccounts/app/token", "POST", "kubernetes.default.svc");
        r.Destination = "10.201.0.20"; r.DestinationPort = 6443;
        return r;
    }
    internal static TrafficRecord Registry(int i, bool layer = false)
    {
        var path = layer
            ? "/v2/team/app/blobs/sha256:" + new string('a', 63) + i.ToString("x")
            : "/v2/team/app/manifests/release-" + i;
        return Http(path);
    }
    internal static TrafficRecord State()
        => Http("/infra/terraform.tfstate", "GET", "state.external.example");
    internal static TrafficRecord Secret()
        => Http("/callback?github_token=ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ123456", "GET", "ci.external.example");
}
