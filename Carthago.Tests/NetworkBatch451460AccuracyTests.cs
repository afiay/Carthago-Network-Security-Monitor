// SPDX-License-Identifier: MIT
// GA R451-R460 — SOURCE CANDIDATE — UNVERIFIED.
// 180 authored xUnit invocations (17 source/adversarial/boundary variants and
// one immutable-profile invariant per rule). ZERO executed. Synthetic records
// are not evidence that an authenticated action or outcome was observed.
using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Carthago.Engine.Rules;
using Carthago.Engine.Rules.Expansion;
using Carthago.Models;
using Xunit;

namespace Carthago.Tests;

public sealed class NetworkBatch451460AccuracyTests
{
    private static readonly DateTime Epoch = new(2026, 10, 30, 9, 0, 0, DateTimeKind.Utc);

    private static readonly (string Id, string Reason, int Port, string Transport,
        string Application, int Threshold, int Confidence, int Window, int Cooldown)[] Rules =
    {
        ("R451", "MQTT_ANONYMOUS_CONNECT_OUTCOME_UNAVAILABLE", 1883, "MQTT", "mqtt.connect", 1, 82, 15, 30),
        ("R452", "DATABASE_RESULT_EXPORT_CORRELATION_UNAVAILABLE", 5432, "TCP", "PostgreSQL", 1, 82, 15, 30),
        ("R453", "MDNS_ENUMERATION_RATE_BASELINE_UNAVAILABLE", 5353, "UDP", "mDNS", 4, 76, 5, 20),
        ("R454", "SSDP_MSEARCH_RESPONSE_CORRELATION_UNAVAILABLE", 1900, "UDP", "SSDP", 1, 76, 5, 20),
        ("R455", "AIRPLAY_NONMEDIA_HOST_ROLE_UNAVAILABLE", 5353, "UDP", "mDNS", 1, 76, 5, 20),
        ("R456", "CHROMECAST_DISCOVERY_BURST_BASELINE_UNAVAILABLE", 5353, "UDP", "mDNS", 4, 76, 5, 20),
        ("R457", "JETDIRECT_PRINTER_IDENTITY_AND_EXPOSURE_UNAVAILABLE", 9100, "TCP", "TCP", 1, 76, 5, 20),
        ("R458", "IPP_OPERATION_AND_RESPONSE_UNAVAILABLE", 631, "TCP", "HTTP", 1, 76, 5, 20),
        ("R459", "SMB_BROWSER_ELECTION_MESSAGE_UNAVAILABLE", 138, "UDP", "SMB", 1, 76, 5, 20),
        ("R460", "NBNS_DISTINCT_NAME_SWEEP_UNAVAILABLE", 137, "UDP", "NBNS", 4, 76, 5, 20)
    };

    public static IEnumerable<object[]> MissingProducerCases()
    {
        foreach (var rule in Rules)
        {
            foreach (var variation in new[]
            {
                "plausible",
                "typed-observation",
                "descriptor-spoof",
                "approved-ops",
                "forged-audit",
                "tls-only",
                "missing-source",
                "malformed-target",
                "secret-placeholder",
                "wrong-direction",
                "wrong-protocol",
                "threshold-burst",
                "claimed-success",
                "duplicate-id",
                "spoofed-service-name",
                "fragmentary-native",
                "after-cooldown"
            })
            {
                yield return new object[] { rule.Id, rule.Reason, rule.Port,
                    rule.Transport, rule.Application, variation };
            }
        }
    }

    private static TrafficRecord Observation(string id, int port, string transport, string application)
    {
        var udp = transport == "UDP";
        var record = new TrafficRecord
        {
            Id = Guid.Parse("d74f5936-2a89-42e4-aed9-b75a62cbe1c9"),
            Source = id == "R452" ? "10.94.2.11" : "8.8.8.8",
            Destination = id == "R452" ? "8.8.8.8" : "10.94.2.10",
            IpVersion = 4,
            Protocol = transport,
            IsTcp = !udp,
            IsUdp = udp,
            SourcePort = 50321,
            DestinationPort = port,
            ApplicationProtocol = application,
            Info = string.Empty,
            Length = id == "R452" ? 12 * 1024 * 1024 : 512,
            L4Len = 512
        };
        switch (id)
        {
            case "R451":
                // A wire parser can label some MQTT CONNECT frames but does
                // not attest anonymous flags or correlated CONNACK success.
                record.MqttWillTopicObserved = true;
                break;
            case "R453":
                record.DnsQname = "_services._dns-sd._udp.local";
                record.DnsQtype = "PTR";
                record.DnsIsResponse = false;
                record.Destination = "224.0.0.251";
                break;
            case "R454":
                record.Info = "M-SEARCH * HTTP/1.1";
                break;
            case "R455":
                record.DnsQname = "_airplay._tcp.local";
                record.DnsQtype = "PTR";
                record.Destination = "224.0.0.251";
                break;
            case "R456":
                record.DnsQname = "_googlecast._tcp.local";
                record.DnsQtype = "PTR";
                record.Destination = "224.0.0.251";
                break;
            case "R458":
                record.HttpMethod = "POST";
                record.HttpUri = "/printers/office";
                record.HttpHost = "printer.example.test";
                break;
        }
        return record;
    }

    private static EvidenceDrivenPrecisionRuleBase CreateRule(string id)
        => id switch
        {
            "R451" => new R451_MQTTAnonymousLoginPatternRule(),
            "R452" => new R452_DatabaseLargeResultExportPatternRule(),
            "R453" => new R453_MDNSServiceEnumerationHighRateRule(),
            "R454" => new R454_SSDPMSEARCHExternalAnswerRule(),
            "R455" => new R455_AirPlayDiscoveryFromNonMediaHostRule(),
            "R456" => new R456_ChromecastDiscoveryBurstRule(),
            "R457" => new R457_PrinterJetDirectExternalAccessRule(),
            "R458" => new R458_IPPPrintingFromExternalHostRule(),
            "R459" => new R459_SMBBrowseElectionAnomalyRule(),
            "R460" => new R460_NetBIOSNameQuerySweepRule(),
            _ => throw new ArgumentOutOfRangeException(nameof(id))
        };

    private static Task<RuleEvaluationResult> Evaluate(string id, TrafficRecord record, int seconds = 0)
    {
        var context = new RuleEvaluationContext(record, Sensitivity.Balanced, Epoch.AddSeconds(seconds));
        return CreateRule(id).EvaluateAsync(context).AsTask();
    }

    private static void AssertMissingProducer(RuleEvaluationResult result, string reason)
    {
        Assert.False(result.Matched);
        Assert.Empty(result.Events);
        Assert.Contains(result.NoMatchReasons, item => item.Code == reason);
    }

    [Theory]
    [MemberData(nameof(MissingProducerCases))]
    public async Task Untrusted_Discovery_Or_Service_Clues_Cannot_Claim_A_Validated_Outcome(
        string id, string reason, int port, string transport, string application, string variation)
    {
        var record = Observation(id, port, transport, application);
        switch (variation)
        {
            case "typed-observation":
                // Preserve the original wire-derived clue, but never infer
                // authenticated outcome, asset role or anomaly baseline.
                Assert.NotNull(record.ApplicationProtocol);
                break;
            case "descriptor-spoof":
                record.Info = id + " verified anonymous login, successful print or enumeration";
                break;
            case "approved-ops":
                record.ProcessName = "approved-inventory.exe";
                record.Info = "scheduled media discovery, print administration, backup and monitoring";
                break;
            case "forged-audit":
                record.HttpRequestHeaders = "X-Trusted-Asset-Role: non-media\r\n" +
                    "X-Authenticated-Audit: true\r\nX-Server-Outcome: success";
                break;
            case "tls-only":
                record.ApplicationProtocol = "TLS";
                record.HttpMethod = null;
                record.HttpUri = null;
                record.HttpHost = null;
                record.DnsQname = null;
                record.DnsQtype = null;
                break;
            case "missing-source":
                record.Source = null;
                break;
            case "malformed-target":
                record.HttpUri = "/%ZZ/%00";
                record.DnsQname = "malformed..local";
                record.Info = "truncated discovery frame";
                break;
            case "secret-placeholder":
                record.HttpUri = "/?token=synthetic-not-a-real-credential";
                record.HttpRequestHeaders = "Authorization: Bearer synthetic-not-a-real-credential";
                break;
            case "wrong-direction":
                record.Source = "10.94.2.11";
                record.Destination = "10.94.2.10";
                break;
            case "wrong-protocol":
                record.Protocol = transport == "TCP" ? "UDP" : "TCP";
                record.IsTcp = transport != "TCP";
                record.IsUdp = transport == "TCP";
                break;
            case "threshold-burst":
                // Even the four-observation defaults R453/R456/R460
                // cannot be satisfied by uncorroborated request shapes.
                for (var i = 0; i < 5; i++)
                    AssertMissingProducer(await Evaluate(id,
                        Observation(id, port, transport, application), i * 10), reason);
                break;
            case "claimed-success":
                record.Info = "CONNACK accepted; IPP job completed; SSDP response verified";
                break;
            case "duplicate-id":
                var duplicate = Observation(id, port, transport, application);
                duplicate.Id = record.Id;
                AssertMissingProducer(await Evaluate(id, duplicate, 20), reason);
                break;
            case "spoofed-service-name":
                record.HttpHost = "claimed-" + id.ToLowerInvariant() + ".example.test";
                record.ProcessName = "verified-printer-server.exe";
                record.ApplicationService = "trusted-discovery";
                break;
            case "fragmentary-native":
                record.Length = 1;
                record.L4Len = 1;
                record.Info = "MQTT CONNECT; mDNS PTR; SSDP M-SEARCH; NBNS query";
                break;
            case "after-cooldown":
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, port, transport, application), 0), reason);
                AssertMissingProducer(await Evaluate(id,
                    Observation(id, port, transport, application), 31 * 60), reason);
                break;
        }

        var result = await Evaluate(id, record, variation == "after-cooldown" ? 62 * 60 : 60);
        if (variation == "missing-source")
        {
            Assert.False(result.Matched);
            Assert.Empty(result.Events);
            Assert.Contains(result.NoMatchReasons, item => item.Code == "MISSING_CORE_TELEMETRY");
        }
        else
        {
            AssertMissingProducer(result, reason);
        }
    }

    public static IEnumerable<object[]> OriginalProfiles()
    {
        yield return new object[] { "R451", 1, 82, 15, 30 };
        yield return new object[] { "R452", 1, 82, 15, 30 };
        yield return new object[] { "R453", 4, 76, 5, 20 };
        yield return new object[] { "R454", 1, 76, 5, 20 };
        yield return new object[] { "R455", 1, 76, 5, 20 };
        yield return new object[] { "R456", 4, 76, 5, 20 };
        yield return new object[] { "R457", 1, 76, 5, 20 };
        yield return new object[] { "R458", 1, 76, 5, 20 };
        yield return new object[] { "R459", 1, 76, 5, 20 };
        yield return new object[] { "R460", 4, 76, 5, 20 };
    }

    [Theory]
    [MemberData(nameof(OriginalProfiles))]
    public void Original_Alert_Mode_Confidence_Threshold_Window_And_Cooldown_Remain(
        string id, int threshold, int confidence, int windowMinutes, int cooldownMinutes)
    {
        var profile = CreateRule(id).PrecisionProfile;

        Assert.Equal(RuleRuntimeMode.Alert, profile.DefaultMode);
        Assert.Equal(threshold, profile.Threshold);
        Assert.Equal(confidence, profile.MinimumConfidence);
        Assert.Equal(TimeSpan.FromMinutes(windowMinutes), profile.Window);
        Assert.Equal(TimeSpan.FromMinutes(cooldownMinutes), profile.Cooldown);
    }
}
