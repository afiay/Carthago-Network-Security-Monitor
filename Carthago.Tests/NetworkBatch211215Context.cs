// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch211215Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 4, 30, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Request(int rule, int index = 0)
    {
        var path = rule switch
        {
            211 => "/bootstrap.ps1",
            212 => "/org/repo/main/install.sh",
            213 => "/archive/file" + index + ".zip?X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=credential" + index + "&X-Amz-Signature=signature" + index,
            214 => "/?list-type=2&prefix=logs/",
            _ => "/container?restype=container&comp=list"
        };
        var host = rule switch
        {
            211 => "scripts.external.example",
            212 => "raw.githubusercontent.com",
            213 or 214 => "bucket.s3.amazonaws.com",
            _ => "tenant.blob.core.windows.net"
        };
        var process = rule switch
        {
            211 => "powershell.exe",
            212 => "curl.exe",
            213 => "rclone.exe",
            _ => "python.exe"
        };
        var r = NetworkBatch166175Context.Http(path);
        r.Id = Guid.NewGuid();
        r.Source = "10.211.0." + Interlocked.Increment(ref _source);
        r.Destination = "198.51.100.211";
        r.HttpHost = host;
        r.HttpRequestHeaders = "Host: " + host;
        r.HttpUserAgent = rule == 212 ? "curl/8.7" : "python-requests/2.31";
        r.ProcessName = process;
        r.Info = rule == 212
            ? "curl https://raw.githubusercontent.com/org/repo/main/install.sh | sh" : "";
        return r;
    }
}
