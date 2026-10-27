// SPDX-License-Identifier: MIT
using System;
using Carthago.Engine.Rules;
using Carthago.Models;

namespace Carthago.Tests;

internal static class AssetBatch056060Context
{
    internal static readonly DateTime T0 = new(2026, 10, 27, 10, 0, 0, DateTimeKind.Utc);
    internal const string MacA = "02:11:22:33:44:55";
    internal const string MacB = "06:11:22:33:44:55";
    internal const string MacC = "0A:11:22:33:44:55";
    internal const string VendorA = "00:11:22:33:44:55";
    internal const string VendorB = "04:33:44:55:66:77";
    internal const string VendorB2 = "04:33:44:88:99:AA";

    internal static RuleEvaluationContext At(int seconds = 0, string ip = "10.56.0.10",
        string mac = MacA, string? info = null, string protocol = "ARP",
        string? headerMac = null)
    {
        var record = new TrafficRecord
        {
            Source = ip,
            Destination = "10.56.0.1",
            Protocol = protocol,
            MacSource = headerMac ?? mac,
            Info = info ?? $"ARP reply {ip} is-at {mac}",
            Length = 60
        };
        return new RuleEvaluationContext(record, Sensitivity.Balanced, T0.AddSeconds(seconds));
    }
}
