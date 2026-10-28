// SPDX-License-Identifier: MIT
using System;
using System.Linq;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;
internal static class NetworkBatch251255Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 21, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, double seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int id)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.251.0.10", Destination = "198.51.100.251",
            SourcePort = 51000, DestinationPort = 80, Protocol = "TCP", IsTcp = true,
            ApplicationProtocol = "HTTP", HttpMethod = "PUT", HttpHost = "new-upload.example",
            HttpUri = "/upload", HttpRequestHeaders = "Host: new-upload.example\nContent-Type: multipart/form-data; boundary=BoundaryXYZ123\nContent-Length: 4096",
            ProcessName = "curl.exe", Length = 512, L4Len = 400, Info = ""
        };
        if (id == 252) {
            r.Source = "10.252.0.10"; r.Destination = "198.51.100.252";
            r.HttpHost = "data.example";
            r.HttpUri = "/upload/ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
            r.HttpRequestHeaders = "Host: data.example\nContent-Length: 4096";
        }
        if (id == 253) {
            r.Source = "10.253.0.10"; r.Destination = "198.51.100.253";
            r.HttpHost = "encoded.example";
            var bytes = Enumerable.Range(0, 128).Select(i => (byte)(i * 37 % 256)).ToArray();
            r.HttpUri = "/upload?data=" + Uri.EscapeDataString(Convert.ToBase64String(bytes));
            r.HttpRequestHeaders = "Host: encoded.example\nContent-Length: 4096";
        }
        if (id == 254) {
            r.Source = "10.254.0.10"; r.Destination = "198.51.100.254";
            r.HttpHost = "chunks.example"; r.HttpUri = "/api/chunks/part";
            r.HttpRequestHeaders = "Host: chunks.example\nContent-Length: 1024";
        }
        if (id == 255) {
            r.Source = "10.255.0.10"; r.Destination = "198.51.100.255";
            r.HttpHost = "uploads.example"; r.HttpUri = "/api/upload";
            r.HttpRequestHeaders = "Host: uploads.example\nContent-Length: 262144000";
        }
        return r;
    }
}
