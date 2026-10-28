// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;
internal static class NetworkBatch246250Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 9, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int id)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.246.0.10", Destination = "198.51.100.246",
            SourcePort = 51000, DestinationPort = 80, Protocol = "TCP", IsTcp = true,
            ApplicationProtocol = "HTTP", HttpMethod = "PUT", HttpHost = "uploads.example",
            HttpUri = "/upload/project-src.zip",
            HttpRequestHeaders = "Host: uploads.example\nContent-Length: 4096",
            ProcessName = "curl.exe", Length = 512, L4Len = 400, Info = ""
        };
        if (id == 247) {
            r.Source = "10.247.0.10"; r.Destination = "198.51.100.247";
            r.DestinationPort = 22; r.ApplicationProtocol = null;
            r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null;
            r.HttpRequestHeaders = null; r.ProcessName = "scp.exe";
            r.Length = 65535; r.L4Len = 65495;
        }
        if (id == 248 || id == 249) {
            r.Source = id == 248 ? "10.248.0.10" : "10.249.0.10";
            r.Destination = id == 248 ? "198.51.100.248" : "198.51.100.249";
            r.DestinationPort = id == 248 ? 21 : 445;
            r.ApplicationProtocol = id == 248 ? "ftp.stor" : "smb2.write.request";
            r.HttpMethod = null; r.HttpHost = null; r.HttpUri = null;
            r.HttpRequestHeaders = null; r.ProcessName = null;
        }
        if (id == 250) {
            r.Source = "10.250.0.10"; r.Destination = "198.51.100.250";
            r.HttpHost = "198.51.100.250"; r.HttpUri = "/upload";
            r.HttpMethod = "POST";
            r.HttpRequestHeaders = "Host: 198.51.100.250\nContent-Length: 20971520";
        }
        return r;
    }
}
