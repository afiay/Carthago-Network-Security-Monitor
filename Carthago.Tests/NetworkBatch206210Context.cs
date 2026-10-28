// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch206210Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 4, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Request(int rule)
    {
        var path = rule switch
        {
            206 => "/team/repo/info/refs?service=git-upload-pack",
            207 => "/team/repo/git-receive-pack",
            208 => "/-/package/private-lib/dist-tags",
            209 => "/beacon?event=postinstall",
            _ => "/packages/private-lib-1.0-py3-none-any.whl"
        };
        var method = rule == 207 ? "POST" : "GET";
        var process = rule switch
        {
            206 or 207 => "git.exe",
            208 => "npm.exe",
            209 => "node.exe",
            _ => "pip.exe"
        };
        var host = "r" + rule + ".external.example";
        var r = NetworkBatch166175Context.Http(path, method);
        r.Id = Guid.NewGuid();
        r.Source = "10.206.0." + Interlocked.Increment(ref _source);
        r.Destination = "198.51.100.206";
        r.HttpHost = host;
        r.HttpRequestHeaders = "Host: " + host;
        r.HttpUserAgent = rule is 206 or 207 ? "git/2.43.0"
            : rule == 210 ? "pip/24.0" : "npm/10.0.0";
        r.ProcessName = process;
        r.Info = "";
        return r;
    }
}
