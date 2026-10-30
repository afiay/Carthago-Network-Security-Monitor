// SPDX-License-Identifier: MIT
// GA R391–R400 — SOURCE CANDIDATE — UNVERIFIED.
// All 120 xUnit invocations are AUTHORED, UNEXECUTED. No tests were run.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch391400AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 3, 0, 0, DateTimeKind.Utc);

    // One documented test row per rule; a name/URI is NOT a validated signature.
    public static IEnumerable<object[]> MissingProducerCases()
    {
        var rules = new (string Id, string Reason, string Host, string Path)[]
        {
            ("R391", "ZEROTIER_JOIN_STATE_PROVENANCE_UNAVAILABLE", "api.zerotier.com", "/api/v1/network/1234567890abcdef/member"),
            ("R392", "CLOUD_CLI_SERVER_ROLE_AND_UA_PROVENANCE_UNAVAILABLE", "management.azure.com", "/subscriptions"),
            ("R393", "COBALT_STRIKE_BEACON_PROFILE_SIGNATURE_UNAVAILABLE", "example.net", "/jquery"),
            ("R394", "COBALT_STRIKE_MALLEABLE_HEADER_PROFILE_UNAVAILABLE", "example.net", "/gate.php"),
            ("R395", "SLIVER_MTLS_AUTHENTICATED_FINGERPRINT_UNAVAILABLE", "example.net", "/callback"),
            ("R396", "MYTHIC_AGENT_CALLBACK_PROVENANCE_UNAVAILABLE", "example.net", "/api/v1"),
            ("R397", "METERPRETER_STAGER_PAYLOAD_SIGNATURE_UNAVAILABLE", "example.net", "/stage"),
            ("R398", "HAVOC_CALLBACK_SIGNATURE_UNAVAILABLE", "example.net", "/callback"),
            ("R399", "BRUTE_RATEL_BADGER_SIGNATURE_UNAVAILABLE", "example.net", "/news.php"),
            ("R400", "COVENANT_GRUNT_CALLBACK_SIGNATURE_UNAVAILABLE", "example.net", "/login/process"),
        };

        foreach (var rule in rules)
        {
            foreach (var variation in new[]
            {
                "plausible", "descriptor-spoof", "generic-path", "forged-audit",
                "tls-only", "wrong-host", "missing-source", "malformed-target",
                "privacy-token", "benign-browser", "burst"
            })
                yield return new object[] { rule.Id, rule.Reason, rule.Host, rule.Path, variation };
        }
    }

    private static TrafficRecord Request(string host, string path)
        => new()
        {
            Id = Guid.NewGuid(),
            Source = "10.94.1.10",
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
            "R391" => new R391_ZeroTierNetworkJoinIndicatorRule().EvaluateAsync(context).AsTask(),
            "R392" => new R392_PublicCloudCLIUserAgentFromServerRule().EvaluateAsync(context).AsTask(),
            "R393" => new R393_CobaltStrikeBeaconURIPatternRule().EvaluateAsync(context).AsTask(),
            "R394" => new R394_CobaltStrikeMalleableC2HeaderPatternRule().EvaluateAsync(context).AsTask(),
            "R395" => new R395_SliverC2MTLSPatternRule().EvaluateAsync(context).AsTask(),
            "R396" => new R396_MythicAgentCallbackPatternRule().EvaluateAsync(context).AsTask(),
            "R397" => new R397_MetasploitMeterpreterStagerPatternRule().EvaluateAsync(context).AsTask(),
            "R398" => new R398_HavocC2CallbackPatternRule().EvaluateAsync(context).AsTask(),
            "R399" => new R399_BruteRatelBadgerPatternRule().EvaluateAsync(context).AsTask(),
            "R400" => new R400_CovenantGruntCallbackPatternRule().EvaluateAsync(context).AsTask(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Missing_Family_Or_Authenticated_Provenance_Fails_Closed(
        string id, string reason, string host, string path, string variation)
    {
        var record = Request(host, path);
        switch (variation)
        {
            case "descriptor-spoof":
                record.Info = id + " successful authenticated callback and agent joined";
                break;
            case "generic-path":
                record.HttpUri = "/api/v1/callback";
                record.Info = "beacon stager implant command and control";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Audit-Result: authenticated success\r\nX-Agent-Verified: true";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpRequestHeaders = null;
                break;
            case "wrong-host":
                record.HttpHost = host + ".attacker.invalid";
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%ZZ/../callback";
                break;
            case "privacy-token":
                record.HttpUri = "/callback?authorization=synthetic-placeholder-not-a-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-placeholder-not-a-credential";
                break;
            case "benign-browser":
                record.HttpUri = "/jquery";
                record.HttpRequestHeaders = "User-Agent: Mozilla/5.0";
                record.ProcessName = "browser.exe";
                break;
            case "burst":
                // Even a repeated generic request cannot manufacture C2 identity.
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
        if (variation == "plausible" || variation == "burst")
            Assert.Contains(result.NoMatchReasons, entry => entry.Code == reason);
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R391", 1, 82 };
        yield return new object[] { "R392", 1, 82 };
        yield return new object[] { "R393", 4, 86 };
        yield return new object[] { "R394", 1, 86 };
        yield return new object[] { "R395", 1, 86 };
        yield return new object[] { "R396", 1, 86 };
        yield return new object[] { "R397", 1, 86 };
        yield return new object[] { "R398", 1, 86 };
        yield return new object[] { "R399", 1, 86 };
        yield return new object[] { "R400", 1, 86 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Alert_Mode_Threshold_And_Confidence_Are_Not_Relaxed(
        string id, int threshold, int confidence)
    {
        var profile = id switch
        {
            "R391" => new R391_ZeroTierNetworkJoinIndicatorRule().PrecisionProfile,
            "R392" => new R392_PublicCloudCLIUserAgentFromServerRule().PrecisionProfile,
            "R393" => new R393_CobaltStrikeBeaconURIPatternRule().PrecisionProfile,
            "R394" => new R394_CobaltStrikeMalleableC2HeaderPatternRule().PrecisionProfile,
            "R395" => new R395_SliverC2MTLSPatternRule().PrecisionProfile,
            "R396" => new R396_MythicAgentCallbackPatternRule().PrecisionProfile,
            "R397" => new R397_MetasploitMeterpreterStagerPatternRule().PrecisionProfile,
            "R398" => new R398_HavocC2CallbackPatternRule().PrecisionProfile,
            "R399" => new R399_BruteRatelBadgerPatternRule().PrecisionProfile,
            "R400" => new R400_CovenantGruntCallbackPatternRule().PrecisionProfile,
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };
        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
    }
}
