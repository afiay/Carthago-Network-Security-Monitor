// SPDX-License-Identifier: MIT
// GA R401–R410 — SOURCE CANDIDATE — UNVERIFIED.
// 120 authored xUnit invocations; NONE executed. No positive family signature
// is currently representable by the packet-only telemetry contract.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch401410AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 4, 0, 0, DateTimeKind.Utc);

    public static IEnumerable<object[]> MissingFamilyProvenanceCases()
    {
        var rules = new (string Id, string Reason, string Name, string Host, string Path)[]
        {
            ("R401", "EMPIRE_STAGER_PROFILE_SIGNATURE_UNAVAILABLE", "Empire Stager URI Pattern", "example.net", "/api/v1/callback"),
            ("R402", "ASYNCRAT_TELEGRAM_AGENT_CORRELATION_UNAVAILABLE", "AsyncRAT Telegram C2 Pattern", "api.telegram.org", "/botplaceholder/sendMessage"),
            ("R403", "REMCOS_PROTOCOL_SIGNATURE_UNAVAILABLE", "Remcos RAT C2 Pattern", "example.net", "/api/v1/callback"),
            ("R404", "AGENT_TESLA_SMTP_EXFIL_PROVENANCE_UNAVAILABLE", "AgentTesla SMTP Exfil Pattern", "smtp.example.net", "/api/v1/callback"),
            ("R405", "QAKBOT_HTTP_PROFILE_SIGNATURE_UNAVAILABLE", "QakBot URI Pattern", "example.net", "/api/v1/callback"),
            ("R406", "EMOTET_LOADER_PAYLOAD_SIGNATURE_UNAVAILABLE", "Emotet Loader URI Pattern", "example.net", "/api/v1/callback"),
            ("R407", "BUMBLEBEE_LOADER_PAYLOAD_SIGNATURE_UNAVAILABLE", "Bumblebee Loader URI Pattern", "example.net", "/api/v1/callback"),
            ("R408", "SOCGHOLISH_FAKE_UPDATE_DELIVERY_PROVENANCE_UNAVAILABLE", "SocGholish FakeUpdate Pattern", "example.net", "/api/v1/callback"),
            ("R409", "RASPBERRY_ROBIN_LNK_EXECUTION_PROVENANCE_UNAVAILABLE", "Raspberry Robin Short LNK Pattern", "example.net", "/api/v1/callback"),
            ("R410", "REDLINE_EXFIL_PAYLOAD_CORRELATION_UNAVAILABLE", "Redline Stealer Exfil Pattern", "example.net", "/api/v1/callback"),
        };
        foreach (var rule in rules)
        {
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "generic-path", "forged-audit",
                "tls-only", "missing-source", "malformed-target", "privacy-token",
                "benign-browser", "family-specific-claim", "burst"
            })
                yield return new object[] { rule.Id, rule.Reason, rule.Name, rule.Host, rule.Path, variation };
        }
    }

    private static TrafficRecord Request(string host, string path)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.94.2.10",
            Destination = "8.8.8.8",
            IpVersion = 4,
            Protocol = "TCP",
            IsTcp = true,
            IsUdp = false,
            SourcePort = 50400,
            DestinationPort = 80,
            ApplicationProtocol = "HTTP",
            HttpMethod = "GET",
            HttpUri = path,
            HttpHost = host,
            HttpRequestHeaders = "User-Agent: synthetic-test-client",
            Info = string.Empty,
            Length = 640,
            L4Len = 640
        };

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return id switch
        {
            "R401" => new R401_EmpireStagerURIPatternRule().EvaluateAsync(context).AsTask(),
            "R402" => new R402_AsyncRATTelegramC2PatternRule().EvaluateAsync(context).AsTask(),
            "R403" => new R403_RemcosRATC2PatternRule().EvaluateAsync(context).AsTask(),
            "R404" => new R404_AgentTeslaSMTPExfilPatternRule().EvaluateAsync(context).AsTask(),
            "R405" => new R405_QakBotURIPatternRule().EvaluateAsync(context).AsTask(),
            "R406" => new R406_EmotetLoaderURIPatternRule().EvaluateAsync(context).AsTask(),
            "R407" => new R407_BumblebeeLoaderURIPatternRule().EvaluateAsync(context).AsTask(),
            "R408" => new R408_SocGholishFakeUpdatePatternRule().EvaluateAsync(context).AsTask(),
            "R409" => new R409_RaspberryRobinShortLNKPatternRule().EvaluateAsync(context).AsTask(),
            "R410" => new R410_RedlineStealerExfilPatternRule().EvaluateAsync(context).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    [Theory]
    [MemberData(nameof(MissingFamilyProvenanceCases))]
    public async Task Untrusted_Family_Clues_Cannot_Emit_Attributed_Alerts(
        string id, string reason, string name, string host, string path, string variation)
    {
        var record = Request(host, path);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = name + " authenticated successful malware callback";
                break;
            case "generic-path":
                record.HttpUri = "/jquery/api/v1/callback";
                record.Info = "beacon stager payload command and control";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Audit-Result: authenticated success\r\nX-Family-Verified: true";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpRequestHeaders = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%ZZ/../callback";
                break;
            case "privacy-token":
                record.HttpUri = "/callback?access_token=synthetic-placeholder-not-a-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-placeholder-not-a-credential";
                break;
            case "benign-browser":
                record.HttpUri = "/api/v1/update";
                record.HttpRequestHeaders = "User-Agent: Mozilla/5.0";
                record.ProcessName = "browser.exe";
                break;
            case "family-specific-claim":
                if (id == "R404")
                {
                    record.ApplicationProtocol = "SMTP";
                    record.DestinationPort = 25;
                    record.HttpMethod = null;
                    record.HttpUri = null;
                    record.HttpRequestHeaders = null;
                    record.Info = "SMTP DATA submitted by agent tesla";
                }
                else if (id == "R409")
                {
                    record.ProcessName = "rundll32.exe";
                    record.Info = "raspberry robin removable-media shortcut executed";
                }
                else if (id == "R402")
                {
                    record.HttpHost = "api.telegram.org";
                    record.HttpMethod = "POST";
                    record.HttpUri = "/botplaceholder/sendMessage";
                    record.Info = "asyncrat Telegram C2 claimed";
                }
                else
                {
                    record.Info = name + " agent payload signature verified";
                    record.ProcessName = "synthetic-client.exe";
                }
                break;
            case "burst":
                // Repeated ordinary requests cannot become validated malware
                // attribution merely by satisfying a time-window threshold.
                for (var i = 0; i < 7; i++)
                {
                    var interim = await Evaluate(id, Request(host, path), i);
                    Assert.False(interim.Matched);
                    Assert.Empty(interim.Events);
                }
                break;
        }

        var result = await Evaluate(id, record, variation == "burst" ? 8 : 0);
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        if (variation is "plausible" or "burst")
            Assert.Contains(result.NoMatchReasons, entry => entry.Code == reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R401", 1, 86 };
        yield return new object[] { "R402", 1, 86 };
        yield return new object[] { "R403", 1, 86 };
        yield return new object[] { "R404", 1, 86 };
        yield return new object[] { "R405", 1, 86 };
        yield return new object[] { "R406", 1, 86 };
        yield return new object[] { "R407", 1, 86 };
        yield return new object[] { "R408", 1, 86 };
        yield return new object[] { "R409", 1, 86 };
        yield return new object[] { "R410", 1, 86 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Profile_Threshold_And_Confidence_Remain_Unchanged(
        string id, int threshold, int confidence)
    {
        var profile = id switch
        {
            "R401" => new R401_EmpireStagerURIPatternRule().PrecisionProfile,
            "R402" => new R402_AsyncRATTelegramC2PatternRule().PrecisionProfile,
            "R403" => new R403_RemcosRATC2PatternRule().PrecisionProfile,
            "R404" => new R404_AgentTeslaSMTPExfilPatternRule().PrecisionProfile,
            "R405" => new R405_QakBotURIPatternRule().PrecisionProfile,
            "R406" => new R406_EmotetLoaderURIPatternRule().PrecisionProfile,
            "R407" => new R407_BumblebeeLoaderURIPatternRule().PrecisionProfile,
            "R408" => new R408_SocGholishFakeUpdatePatternRule().PrecisionProfile,
            "R409" => new R409_RaspberryRobinShortLNKPatternRule().PrecisionProfile,
            "R410" => new R410_RedlineStealerExfilPatternRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(30), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(45), profile.Cooldown);
    }
}
