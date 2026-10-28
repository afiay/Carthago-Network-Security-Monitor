// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;
namespace Carthago.Tests;
internal static class NetworkBatch241245Context
{
    internal static readonly DateTime Origin = new(2026, 10, 28, 7, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));
    internal static TrafficRecord Sample(int id)
    {
        var r = new TrafficRecord {
            Id = Guid.NewGuid(), Source = "10.241.0.10", Destination = "10.241.0.20",
            SourcePort = 51000, DestinationPort = 47808, Protocol = "UDP",
            IsUdp = true, ApplicationProtocol = "bacnet.whois", Info = "", Length = 300, L4Len = 250
        };
        if (id == 242) {
            r.Source = "10.242.0.10"; r.Destination = "198.51.100.42";
            r.DestinationPort = 123; r.ApplicationProtocol = "ntp.mode7.monlist";
        }
        if (id >= 243) {
            r.Source = "10.243.0.10"; r.Destination = "198.51.100.43";
            r.Protocol = "TCP"; r.IsUdp = false; r.IsTcp = true;
            r.DestinationPort = 80; r.ApplicationProtocol = "HTTP";
            r.HttpMethod = "PUT"; r.HttpHost = "uploads.example";
            r.HttpUri = id == 243 ? "/upload/backup_2026.zip"
                : id == 244 ? "/upload/customers_dump.sql.gz" : "/upload/credentials.pem";
            r.HttpRequestHeaders = "Host: uploads.example\nContent-Length: "
                + (id == 243 ? "104857600" : "4096");
            r.ProcessName = "curl.exe";
        }
        return r;
    }
}
