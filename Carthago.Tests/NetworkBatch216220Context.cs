// SPDX-License-Identifier: MIT
using System;
using System.Threading;
using Carthago.Engine.Rules;
using Carthago.Models;
using Carthago.Services;

namespace Carthago.Tests;
internal static class NetworkBatch216220Context
{
    private static int _source = 20;
    internal static readonly DateTime Origin = new(2026, 10, 28, 5, 0, 0, DateTimeKind.Utc);
    internal static RuleEvaluationContext At(TrafficRecord r, int seconds = 0)
        => new(r, Sensitivity.Balanced, Origin.AddSeconds(seconds));

    internal static TrafficRecord Request(int rule)
    {
        var host = rule switch
        {
            216 => "storage.googleapis.com",
            217 => "hooks.slack.com",
            218 => "discord.com",
            219 => "api.telegram.org",
            _ => "pastebin.com"
        };
        var path = rule switch
        {
            216 => "/storage/v1/b/demo-bucket/o?prefix=logs",
            217 => "/services/T0123/B0456/secretSlackWebhookToken123456789",
            218 => "/api/webhooks/123456789012345/secretDiscordToken1234567890",
            219 => "/bot123456789:secretTelegramBotToken1234567890/sendDocument",
            _ => "/api/pastes?token=secretPasteQuery123456789"
        };
        var r = NetworkBatch166175Context.Http(path, rule == 216 ? "GET" : "POST");
        r.Id = Guid.NewGuid();
        r.Source = "10.216.0." + Interlocked.Increment(ref _source);
        r.Destination = "198.51.100.216";
        r.SourcePort = 51000;
        r.DestinationPort = 80;
        r.Protocol = "TCP";
        r.ApplicationProtocol = "HTTP";
        r.ApplicationService = "HTTP";
        r.IsTcp = true;
        r.IsUdp = false;
        r.HttpHost = host;
        r.HttpUri = path;
        r.HttpRequestHeaders = rule == 216 ? "Host: " + host : "Host: " + host +
            "\r\nContent-Type: multipart/form-data; boundary=abc123" +
            "\r\nContent-Length: " + (rule == 220 ? "250000" : "70000");
        r.HttpUserAgent = "python-requests/2.31";
        r.ProcessName = "python.exe";
        r.Info = "";
        r.Length = 1024;
        r.L4Len = 512;
        return r;
    }

    internal static void ChangeHost(TrafficRecord r, string host)
    {
        r.HttpHost = host;
        r.HttpRequestHeaders = r.HttpRequestHeaders!.Replace(
            r.HttpRequestHeaders.Split('\n')[0].TrimEnd('\r'), "Host: " + host);
    }
    internal static void Small(TrafficRecord r)
    {
        r.HttpRequestHeaders = "Host: " + r.HttpHost + "\r\nContent-Length: 120";
    }
}
